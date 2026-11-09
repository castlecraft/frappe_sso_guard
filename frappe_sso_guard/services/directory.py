# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from typing import Any
from urllib.parse import quote

import frappe
import requests

from frappe_sso_guard.services.idp import (
	HTTP_TIMEOUT_SECONDS,
	SSONotConfiguredError,
	get_openid_configuration,
)

ACCOUNT_ACTIVE = "Active"
ACCOUNT_DISABLED = "Disabled"
ACCOUNT_REMOVED = "Removed"
ACCOUNT_UNKNOWN = "Unknown"

GRAPH_USERS_URL = "https://graph.microsoft.com/v1.0/users"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
KEYCLOAK_REALM_PATH = "/realms/"
KEYCLOAK_ADMIN_REALM_PATH = "/admin/realms/"


class DirectoryError(Exception):
	"""The identity provider did not say what became of an account, so nothing may be concluded from it."""


class DirectoryClient:
	"""Reads whether accounts still exist and are enabled at the identity provider.

	It holds a read-only credential from the site config, as a System Manager must not be able to
	point it elsewhere: Keycloak's view-users role, or Graph's User.Read.All.
	"""

	def __init__(self, idp_type: str, issuer: str):
		conf = frappe.conf or {}
		self.client_id = conf.get("sso_directory_client_id")
		self.client_secret = conf.get("sso_directory_client_secret")
		if not (self.client_id and self.client_secret):
			raise SSONotConfiguredError("sso_directory_client_id and its secret are not in site_config.json")
		if idp_type not in ("Keycloak", "Entra ID"):
			raise SSONotConfiguredError(f"Accounts cannot be read from a provider of type {idp_type}")
		if idp_type == "Keycloak" and KEYCLOAK_REALM_PATH not in issuer:
			raise SSONotConfiguredError("The issuer does not name a Keycloak realm")

		self.idp_type = idp_type
		self.issuer = issuer
		self.token_endpoint = get_openid_configuration(issuer)["token_endpoint"]
		self.access_token = None

	def get_account_status(self, identifier: str) -> str:
		"""What the identity provider says of the account with this bound identifier."""
		if self.idp_type == "Keycloak":
			base_url = self.issuer.replace(KEYCLOAK_REALM_PATH, KEYCLOAK_ADMIN_REALM_PATH, 1)
			url = f"{base_url}/users/{quote(identifier, safe='')}"
			field, params = "enabled", None
		else:
			# Bound as oid:tid, and the pinned issuer already names the tenant.
			object_id = identifier.partition(":")[0]
			url = f"{GRAPH_USERS_URL}/{quote(object_id, safe='')}"
			field, params = "accountEnabled", {"$select": "accountEnabled"}

		response = self._get(url, params)
		if response.status_code == 404:
			return ACCOUNT_REMOVED
		if response.status_code != 200:
			raise DirectoryError(f"The identity provider answered {response.status_code}")

		enabled = response.json().get(field)
		if enabled is None:
			return ACCOUNT_UNKNOWN
		return ACCOUNT_ACTIVE if enabled else ACCOUNT_DISABLED

	def _get(self, url: str, params: dict[str, str] | None) -> requests.Response:
		response = self._get_with_token(url, params)
		if response.status_code == 401:
			# A run takes longer than a Keycloak service account's token lives.
			self.access_token = None
			response = self._get_with_token(url, params)
		return response

	def _get_with_token(self, url: str, params: dict[str, str] | None) -> requests.Response:
		try:
			return requests.get(
				url,
				params=params,
				headers={"Authorization": f"Bearer {self._get_access_token()}"},
				timeout=HTTP_TIMEOUT_SECONDS,
			)
		except requests.RequestException as e:
			raise DirectoryError(f"The identity provider could not be reached: {type(e).__name__}") from e

	def _get_access_token(self) -> str:
		if self.access_token:
			return self.access_token

		data: dict[str, Any] = {
			"grant_type": "client_credentials",
			"client_id": self.client_id,
			"client_secret": self.client_secret,
		}
		if self.idp_type == "Entra ID":
			data["scope"] = GRAPH_SCOPE

		response = requests.post(self.token_endpoint, data=data, timeout=HTTP_TIMEOUT_SECONDS)
		if response.status_code != 200:
			raise DirectoryError(f"The identity provider refused the credential: {response.status_code}")

		self.access_token = response.json().get("access_token")
		if not self.access_token:
			raise DirectoryError("The identity provider returned no access token")
		return self.access_token
