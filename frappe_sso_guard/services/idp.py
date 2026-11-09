# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import base64
import hashlib
import hmac
from typing import Any

import frappe
import jwt
import requests
from jwt import PyJWKClient

DISCOVERY_PATH = "/.well-known/openid-configuration"
SIGNING_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]
CLOCK_SKEW_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 10
JWKS_CACHE: dict[str, PyJWKClient] = {}
DEFAULT_SESSION_MAX_HOURS_LIMIT = 12


class SSONotConfiguredError(Exception):
	"""The site lacks a setting the sign-in cannot safely run without."""


def get_provider_key() -> str | None:
	"""The Social Login Key that bound Users are bound through."""
	conf = frappe.conf or {}
	return frappe.db.get_single_value("SSO Identity Settings", "social_login_key") or conf.get(
		"sso_provider_key"
	)


def get_session_max_hours_limit() -> int:
	"""The longest session the site allows. Only the server can raise it; a System Manager can shorten it."""
	conf = frappe.conf or {}
	return int(conf.get("sso_session_max_hours_limit") or DEFAULT_SESSION_MAX_HOURS_LIMIT)


def get_sso_config() -> dict[str, Any]:
	"""Retrieves SSO configuration from site_config and SSO Identity Settings."""
	conf = frappe.conf or {}
	force_sso = int(conf.get("force_sso", 1))
	sso_issuer = conf.get("sso_issuer")

	# Fetch single settings doc
	settings = frappe.get_single("SSO Identity Settings")
	social_login_key = settings.social_login_key or conf.get("sso_provider_key")
	limit = get_session_max_hours_limit()
	session_max_hours = min(int(settings.session_max_hours or limit), limit)
	idp_type = settings.idp_type or "Keycloak"

	return {
		"force_sso": force_sso,
		"sso_issuer": sso_issuer,
		"social_login_key": social_login_key,
		"session_max_hours": session_max_hours,
		"idp_type": idp_type,
		"enable_single_logout": bool(settings.enable_single_logout),
		"admin_notification_emails": settings.admin_notification_emails,
	}


def get_sign_in_config() -> dict[str, Any]:
	"""The SSO configuration, refusing a site without a pinned issuer or a Social Login Key.

	The issuer has no fallback to the Social Login Key: a System Manager can edit that record, and
	pointing it at another identity provider would let whoever runs that provider sign in as anyone.
	"""
	config = get_sso_config()
	if not config["sso_issuer"]:
		raise SSONotConfiguredError("sso_issuer is not set in site_config.json")
	if not config["social_login_key"]:
		raise SSONotConfiguredError("No Social Login Key is configured for single sign-on")
	return config


def get_openid_configuration(issuer_url: str) -> dict[str, Any]:
	"""Fetches the OpenID Connect discovery document from the pinned issuer."""
	cache_key = f"oidc_discovery_{issuer_url}"
	cached = frappe.cache.get_value(cache_key)
	if cached:
		return cached

	discovery_url = issuer_url.rstrip("/") + DISCOVERY_PATH
	resp = requests.get(discovery_url, timeout=HTTP_TIMEOUT_SECONDS)
	resp.raise_for_status()
	config = resp.json()
	if config.get("issuer") != issuer_url:
		raise ValueError("The discovery document names another issuer than the pinned one")
	if not all(config.get(field) for field in ("authorization_endpoint", "token_endpoint", "jwks_uri")):
		raise ValueError("The discovery document lacks an endpoint the sign-in needs")

	frappe.cache.set_value(cache_key, config, expires_in_sec=86400)
	return config


def get_jwk_client(jwks_uri: str) -> PyJWKClient:
	"""Returns a cached PyJWKClient instance for token signature verification."""
	if jwks_uri not in JWKS_CACHE:
		JWKS_CACHE[jwks_uri] = PyJWKClient(
			jwks_uri, cache_keys=True, max_cached_keys=16, timeout=HTTP_TIMEOUT_SECONDS
		)
	return JWKS_CACHE[jwks_uri]


def make_code_challenge(code_verifier: str) -> str:
	"""The S256 PKCE challenge for a verifier."""
	digest = hashlib.sha256(code_verifier.encode()).digest()
	return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def exchange_code(
	token_endpoint: str,
	code: str,
	redirect_uri: str,
	client_id: str,
	client_secret: str,
	code_verifier: str,
) -> dict[str, Any]:
	"""Exchanges an authorization code for the identity provider's tokens."""
	resp = requests.post(
		token_endpoint,
		data={
			"grant_type": "authorization_code",
			"code": code,
			"redirect_uri": redirect_uri,
			"client_id": client_id,
			"client_secret": client_secret,
			"code_verifier": code_verifier,
		},
		timeout=HTTP_TIMEOUT_SECONDS,
	)
	resp.raise_for_status()
	return resp.json()


def verify_id_token(
	id_token: str,
	jwks_uri: str,
	expected_issuer: str,
	expected_audience: str,
	expected_nonce: str,
) -> dict[str, Any]:
	"""Verifies the ID token's signature, issuer, audience, expiry and nonce, or raises."""
	signing_key = get_jwk_client(jwks_uri).get_signing_key_from_jwt(id_token)

	claims = jwt.decode(
		id_token,
		signing_key.key,
		algorithms=SIGNING_ALGORITHMS,
		audience=expected_audience,
		issuer=expected_issuer,
		leeway=CLOCK_SKEW_SECONDS,
		options={"require": REQUIRED_CLAIMS},
	)

	if not hmac.compare_digest((claims.get("nonce") or "").encode(), expected_nonce.encode()):
		raise ValueError("ID token nonce mismatch")

	return claims
