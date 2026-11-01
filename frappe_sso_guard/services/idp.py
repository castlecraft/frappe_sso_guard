from typing import Any, Optional

import frappe
import jwt
import requests
from jwt import PyJWKClient

DISCOVERY_PATH = "/.well-known/openid-configuration"
JWKS_CACHE: dict[str, PyJWKClient] = {}


def get_sso_config() -> dict[str, Any]:
	"""Retrieves SSO configuration from site_config and SSO Identity Settings."""
	conf = frappe.conf or {}
	force_sso = int(conf.get("force_sso", 1))
	sso_issuer = conf.get("sso_issuer")

	# Fetch single settings doc
	settings = frappe.get_single("SSO Identity Settings")
	social_login_key = settings.social_login_key or conf.get("sso_provider_key")
	session_max_hours = int(settings.session_max_hours or 12)
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


def get_social_login_key_doc(key_name: str | None = None):
	"""Retrieves the Social Login Key document and decrypted client secret."""
	if not key_name:
		config = get_sso_config()
		key_name = config.get("social_login_key")

	if not key_name:
		frappe.throw("Social Login Key is not configured in SSO Identity Settings or site_config.json")

	key_doc = frappe.get_doc("Social Login Key", key_name)
	client_secret = key_doc.get_password("client_secret")
	return key_doc, client_secret


def get_openid_configuration(issuer_url: str) -> dict[str, Any]:
	"""Fetches the OpenID Connect discovery document from the pinned issuer."""
	cache_key = f"oidc_discovery_{issuer_url}"
	cached = frappe.cache.get_value(cache_key)
	if cached:
		return cached

	discovery_url = issuer_url.rstrip("/") + DISCOVERY_PATH
	resp = requests.get(discovery_url, timeout=10)
	resp.raise_for_status()
	config = resp.json()
	frappe.cache.set_value(cache_key, config, expires_in_sec=86400)
	return config


def get_jwk_client(jwks_uri: str) -> PyJWKClient:
	"""Returns a cached PyJWKClient instance for token signature verification."""
	if jwks_uri not in JWKS_CACHE:
		JWKS_CACHE[jwks_uri] = PyJWKClient(jwks_uri, cache_keys=True, max_cached_keys=16)
	return JWKS_CACHE[jwks_uri]


def verify_id_token(
	id_token: str,
	expected_issuer: str,
	expected_audience: str,
	expected_nonce: str | None = None,
) -> dict[str, Any]:
	"""Verifies the ID token against the pinned issuer's JWKS.

	Checks signature, issuer, audience, nonce, and expiration.
	"""
	discovery = get_openid_configuration(expected_issuer)
	jwks_uri = discovery.get("jwks_uri")
	if not jwks_uri:
		raise ValueError(f"No jwks_uri found in discovery document for issuer {expected_issuer}")

	jwk_client = get_jwk_client(jwks_uri)
	signing_key = jwk_client.get_signing_key_from_jwt(id_token)

	decode_options = {
		"verify_signature": True,
		"verify_iss": True,
		"verify_aud": True,
		"verify_exp": True,
	}

	claims = jwt.decode(
		id_token,
		signing_key.key,
		algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
		audience=expected_audience,
		issuer=expected_issuer,
		options=decode_options,
	)

	if expected_nonce and claims.get("nonce") != expected_nonce:
		raise ValueError(f"ID token nonce mismatch. Expected {expected_nonce}, got {claims.get('nonce')}")

	return claims
