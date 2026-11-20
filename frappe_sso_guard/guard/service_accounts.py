# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
import jwt
import requests
from frappe.auth import validate_ip_address

from frappe_sso_guard.guard.session_guard import holds_admin_role, is_break_glass_user
from frappe_sso_guard.services.idp import (
	CLOCK_SKEW_SECONDS,
	REQUIRED_CLAIMS,
	SIGNING_ALGORITHMS,
	get_jwk_client,
	get_openid_configuration,
)


def eligible_user(user: str) -> bool:
	return bool(
		user
		and user not in frappe.STANDARD_USERS
		and not is_break_glass_user(user)
		and frappe.db.get_value("User", {"name": user, "enabled": 1}, "name") == user
		and not holds_admin_role(user)
	)


def authenticate():
	"""Authenticate an incoming Keycloak service token for this API request."""
	issuer = frappe.conf.get("sso_issuer")
	audience = frappe.conf.get("sso_service_token_audience")
	if not issuer or not audience:
		return
	header = frappe.get_request_header("Authorization", "").split()
	if len(header) != 2 or header[0].lower() != "bearer" or not frappe.request.path.startswith("/api/"):
		return
	token = header[1]
	try:
		# Route by issuer only. Discovery always uses the issuer pinned by the site operator.
		hint = jwt.decode(token, options={"verify_signature": False})
	except jwt.PyJWTError:
		return
	if hint.get("iss") != issuer:
		return

	try:
		discovery = get_openid_configuration(issuer)
		key = get_jwk_client(discovery["jwks_uri"]).get_signing_key_from_jwt(token)
		claims = jwt.decode(
			token,
			key.key,
			algorithms=SIGNING_ALGORITHMS,
			issuer=issuer,
			audience=audience,
			leeway=CLOCK_SKEW_SECONDS,
			options={"require": [*REQUIRED_CLAIMS, "azp", "typ"]},
		)
	except jwt.PyJWTError, requests.RequestException, ValueError, TypeError, OverflowError:
		raise frappe.AuthenticationError from None

	client_id = claims["azp"]
	if claims["typ"] != "Bearer" or not isinstance(client_id, str) or not isinstance(claims["sub"], str):
		raise frappe.AuthenticationError
	mapping = frappe.db.get_value(
		"SSO Service Account",
		{"client_id": client_id, "enabled": 1},
		["client_id", "subject", "issuer", "user"],
		as_dict=True,
	)
	# Identity claims are case-sensitive, including on databases with a case-insensitive collation.
	if not mapping or (mapping.issuer, mapping.client_id, mapping.subject) != (
		issuer,
		client_id,
		claims["sub"],
	):
		raise frappe.AuthenticationError
	if not eligible_user(mapping.user):
		raise frappe.AuthenticationError
	if frappe.session.user not in ("", "Guest", mapping.user):
		raise frappe.AuthenticationError
	validate_ip_address(mapping.user)
	if frappe.session.user == mapping.user:
		return
	# set_user resets form_dict; API method arguments must survive authentication.
	form_dict = frappe.local.form_dict
	frappe.set_user(mapping.user)
	frappe.local.form_dict = form_dict
