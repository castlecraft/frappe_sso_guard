# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import json
import os
from pathlib import Path
from typing import Any

import click
import frappe
import requests
from frappe.installer import update_site_config
from frappe.utils import get_url

KEYCLOAK_DEFAULT_URL = "http://localhost:8080"
KEYCLOAK_PROVIDER_KEY = "keycloak_local"
KEYCLOAK_TIMEOUT_SECONDS = 30


def setup_dex():
	if not frappe.conf.developer_mode:
		frappe.throw("setup_dex configures a local test identity provider: developer mode only.")

	if not frappe.db.exists("Social Login Key", "dex_local"):
		doc = frappe.get_doc(
			{
				"doctype": "Social Login Key",
				"provider_name": "dex_local",
				"base_url": "http://dex.localhost:5556/dex",
				"authorize_url": "/api/method/frappe_sso_guard.api.callback.start",
				"access_token_url": "http://dex.localhost:5556/dex/token",
				"client_id": "frappe-sso-client",
				"client_secret": "frappe_sso_secret",
				"redirect_url": "http://localhost:8000/api/method/frappe_sso_guard.api.callback.handle_callback",
				"auth_url_data": json.dumps({"response_type": "code", "scope": "openid email profile"}),
				"enable_social_login": 1,
			}
		)
		doc.insert(ignore_permissions=True)
		click.secho("Created Social Login Key: dex_local", fg="green")
	else:
		doc = frappe.get_doc("Social Login Key", "dex_local")
		doc.authorize_url = "/api/method/frappe_sso_guard.api.callback.start"
		doc.auth_url_data = json.dumps({"response_type": "code", "scope": "openid email profile"})
		doc.save(ignore_permissions=True)
		click.secho("Updated Social Login Key: dex_local with OIDC scopes", fg="yellow")

	settings = frappe.get_single("SSO Identity Settings")
	settings.social_login_key = "dex_local"
	settings.idp_type = "Generic OIDC"
	settings.enable_single_logout = 0
	settings.save(ignore_permissions=True)
	frappe.db.commit()
	click.secho("Configured SSO Identity Settings for Dex", fg="green")


def setup_keycloak():
	"""Creates a test realm in a running Keycloak and points this site at it. See docs/04."""
	if not frappe.conf.developer_mode:
		frappe.throw("setup_keycloak configures a local test identity provider: developer mode only.")

	admin_password = os.environ.get("KEYCLOAK_PASSWORD")
	if not admin_password:
		frappe.throw("Set KEYCLOAK_PASSWORD to the password of Keycloak's admin user.")

	url = os.environ.get("KEYCLOAK_URL", KEYCLOAK_DEFAULT_URL).rstrip("/")
	realm = load_keycloak_realm()
	secrets = create_keycloak_realm(url, admin_password, realm, get_url())
	issuer = f"{url}/realms/{realm['realm']}"

	key = (
		frappe.get_doc("Social Login Key", KEYCLOAK_PROVIDER_KEY)
		if frappe.db.exists("Social Login Key", KEYCLOAK_PROVIDER_KEY)
		else frappe.new_doc("Social Login Key")
	)
	key.update(
		{
			"provider_name": KEYCLOAK_PROVIDER_KEY,
			"social_login_provider": "Custom",
			"base_url": issuer,
			"authorize_url": "/api/method/frappe_sso_guard.api.callback.start",
			"access_token_url": f"{issuer}/protocol/openid-connect/token",
			"client_id": secrets["client_id"],
			"client_secret": secrets["client_secret"],
			"redirect_url": "/api/method/frappe_sso_guard.api.callback.handle_callback",
			"auth_url_data": json.dumps({"response_type": "code", "scope": "openid email profile"}),
			"enable_social_login": 1,
			# A site that holds none of the realm's people yet creates them at their first sign-in.
			"sign_ups": "Allow",
		}
	)
	key.save(ignore_permissions=True)

	settings = frappe.get_single("SSO Identity Settings")
	settings.social_login_key = KEYCLOAK_PROVIDER_KEY
	settings.idp_type = "Keycloak"
	settings.enable_single_logout = 1
	settings.enable_reconciliation = 1
	settings.save(ignore_permissions=True)

	update_site_config("sso_issuer", issuer)
	update_site_config("sso_directory_client_id", secrets["directory_client_id"])
	update_site_config("sso_directory_client_secret", secrets["directory_client_secret"])
	frappe.db.commit()

	click.secho(f"Configured this site for {issuer}", fg="green")
	click.echo("Sign in as sso.active, sso.unverified or sso.leaver; sso.disabled is refused.")
	click.echo(f"Their password, generated for this realm: {secrets['user_password']}")


def load_keycloak_realm() -> dict[str, Any]:
	app_root = Path(frappe.get_app_path("frappe_sso_guard")).parent
	return json.loads((app_root / "dev" / "keycloak" / "realm.json").read_text())


def create_keycloak_realm(
	url: str, admin_password: str, realm: dict[str, Any], site_url: str
) -> dict[str, str]:
	"""Replaces the realm with this one, with new secrets, as nothing in git may hold a credential."""
	secrets = {"user_password": frappe.generate_hash(length=24)}
	for client in realm["clients"]:
		client["secret"] = frappe.generate_hash(length=32)
		if client.get("serviceAccountsEnabled"):
			secrets["directory_client_id"] = client["clientId"]
			secrets["directory_client_secret"] = client["secret"]
		else:
			secrets["client_id"] = client["clientId"]
			secrets["client_secret"] = client["secret"]
			client["redirectUris"].append(f"{site_url}/*")
	for user in realm["users"]:
		if not user.get("serviceAccountClientId"):
			user["credentials"] = [
				{"type": "password", "value": secrets["user_password"], "temporary": False}
			]

	headers = {"Authorization": f"Bearer {get_keycloak_admin_token(url, admin_password)}"}
	requests.delete(f"{url}/admin/realms/{realm['realm']}", headers=headers, timeout=KEYCLOAK_TIMEOUT_SECONDS)
	requests.post(
		f"{url}/admin/realms", headers=headers, json=realm, timeout=KEYCLOAK_TIMEOUT_SECONDS
	).raise_for_status()
	return secrets


def get_keycloak_admin_token(url: str, admin_password: str) -> str:
	response = requests.post(
		f"{url}/realms/master/protocol/openid-connect/token",
		data={
			"grant_type": "password",
			"client_id": "admin-cli",
			"username": "admin",
			"password": admin_password,
		},
		timeout=KEYCLOAK_TIMEOUT_SECONDS,
	)
	response.raise_for_status()
	return response.json()["access_token"]
