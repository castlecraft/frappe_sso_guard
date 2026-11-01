import json
from datetime import timedelta

import frappe
import jwt
import requests
from frappe.utils import now_datetime
from frappe.utils.oauth import consume_oauth_state
from jwt import PyJWKClient


@frappe.whitelist(allow_guest=True)
def handle_callback(code: str | None = None, state: str | None = None, error: str | None = None):
	"""Minimal, reliable OIDC callback:

	1. Validates state using Frappe's native consume_oauth_state().
	2. Exchanges code for tokens.
	3. Verifies ID token signature via JWKS against pinned sso_issuer.
	4. Matches user by immutable ID (sub or oid+tid).
	5. Logs in via Frappe's LoginManager.
	"""
	if error:
		frappe.respond_as_web_page(
			"Single Sign-On Failed", f"Identity provider returned error: {error}", http_status_code=403
		)
		return

	if not code or not state:
		frappe.respond_as_web_page(
			"Single Sign-On Failed", "Missing authorization code or state.", http_status_code=400
		)
		return

	# 1. Validate state using Frappe's native single-use cache
	redirect_to = consume_oauth_state(state)
	if redirect_to is None:
		frappe.respond_as_web_page(
			"Single Sign-On Failed",
			"Invalid state or session expired. Please sign in again.",
			http_status_code=403,
		)
		return

	redirect_to = redirect_to or "/app"

	# 2. Get Site Config & Social Login Key
	conf = frappe.conf or {}
	key_name = conf.get("sso_provider_key")
	if not key_name:
		key_name = frappe.db.get_single_value("SSO Identity Settings", "social_login_key")

	if not key_name:
		frappe.throw("sso_provider_key is not configured in site_config.json")

	key_doc = frappe.get_doc("Social Login Key", key_name)
	client_secret = key_doc.get_password("client_secret")
	sso_issuer = conf.get("sso_issuer") or key_doc.base_url

	# 3. Exchange code for tokens at IdP token endpoint
	token_endpoint = key_doc.access_token_url
	if not token_endpoint:
		discovery_resp = requests.get(
			sso_issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=10
		)
		discovery_resp.raise_for_status()
		token_endpoint = discovery_resp.json().get("token_endpoint")

	callback_url = f"{frappe.utils.get_url()}/api/method/frappe_sso_guard.api.callback.handle_callback"

	token_payload = {
		"grant_type": "authorization_code",
		"code": code,
		"redirect_uri": callback_url,
		"client_id": key_doc.client_id,
		"client_secret": client_secret,
	}

	try:
		token_resp = requests.post(token_endpoint, data=token_payload, timeout=10)
		token_resp.raise_for_status()
		tokens = token_resp.json()
	except Exception as e:
		frappe.respond_as_web_page(
			"Single Sign-On Failed", f"Token exchange failed: {e!s}", http_status_code=502
		)
		return

	id_token = tokens.get("id_token")
	if not id_token:
		frappe.respond_as_web_page(
			"Single Sign-On Failed", "IdP did not return an ID token.", http_status_code=502
		)
		return

	# 4. Verify ID Token signature against JWKS
	try:
		jwks_uri = f"{sso_issuer.rstrip('/')}/keys"
		jwk_client = PyJWKClient(jwks_uri, cache_keys=True)
		signing_key = jwk_client.get_signing_key_from_jwt(id_token)
		claims = jwt.decode(
			id_token,
			signing_key.key,
			algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
			audience=key_doc.client_id,
			issuer=sso_issuer,
			options={"verify_signature": True, "verify_iss": True, "verify_aud": True, "verify_exp": True},
		)
	except Exception as e:
		frappe.respond_as_web_page(
			"Single Sign-On Failed", f"ID token verification failed: {e!s}", http_status_code=403
		)
		return

	# 5. Extract immutable identifier
	sub = claims.get("sub")
	oid = claims.get("oid")
	tid = claims.get("tid")
	immutable_id = f"{oid}:{tid}" if (oid and tid) else (oid or sub)
	email = (claims.get("email") or "").lower()

	if not immutable_id:
		frappe.throw("Token claims missing sub or oid.")

	# 6. Find or create user
	user = frappe.db.get_value("User Social Login", {"provider": key_name, "userid": immutable_id}, "parent")

	if not user and email:
		existing = frappe.db.get_value("User", {"email": email}, "name")
		if existing:
			user_doc = frappe.get_doc("User", existing)
			user_doc.append("social_logins", {"provider": key_name, "userid": immutable_id})
			user_doc.save(ignore_permissions=True)
			user = existing
		else:
			new_user = frappe.get_doc(
				{
					"doctype": "User",
					"email": email,
					"first_name": claims.get("name") or claims.get("given_name") or email,
					"enabled": 1,
					"send_welcome_email": 0,
					"user_type": "System User",
					"social_logins": [{"provider": key_name, "userid": immutable_id}],
				}
			)
			new_user.flags.ignore_permissions = True
			new_user.flags.ignore_password_policy = True
			new_user.insert(ignore_permissions=True)
			user = new_user.name

	if not user:
		frappe.throw(f"Could not map user for identifier {immutable_id}")

	# 7. Open Session
	frappe.flags.oidc_session_authorized = True
	frappe.local.login_manager.login_as(user)

	# Commit DB write before redirecting (GET request)
	frappe.db.commit()

	# 8. Clean redirect to desk/app
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = redirect_to
