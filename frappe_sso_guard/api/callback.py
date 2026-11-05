# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import frappe
import jwt
import requests
from frappe import _
from frappe.utils.oauth import (
	OAUTH_LOGIN_FLOW_CACHE_PREFIX,
	consume_oauth_state,
	get_oauth_keys,
	get_redirect_uri,
	redirect_post_login,
)

from frappe_sso_guard.services.audit import log_audit_event
from frappe_sso_guard.services.idp import (
	SSONotConfiguredError,
	exchange_code,
	get_openid_configuration,
	get_sign_in_config,
	make_code_challenge,
	verify_id_token,
)
from frappe_sso_guard.services.user_matching import SignInRefused, find_or_bind_user

FLOW_CACHE_PREFIX = "frappe_sso_guard_flow"
FLOW_COOKIE_PREFIX = "sso_flow_"
# As long as Frappe keeps the state this flow belongs to.
FLOW_LIFETIME_SECONDS = 600
DEFAULT_SCOPE = "openid email profile"


@frappe.whitelist(allow_guest=True)
def start(state: str | None = None):
	"""Sends the visitor to the identity provider with a nonce and PKCE, bound to this browser.

	The Social Login Key's Authorize URL points here, so the login page's button arrives with the
	state Frappe created. Frappe's link cannot carry these itself: its parameters are fixed in the
	Social Login Key, and these must differ per sign-in.
	"""
	if not state or frappe.cache.get_value(f"{OAUTH_LOGIN_FLOW_CACHE_PREFIX}:{state}") is None:
		log_audit_event(
			event_type="Session Refused",
			status="Refused",
			details={"reason": "Sign-in started with an unknown state"},
			persist=False,
		)
		return _show_failure(_("Your sign-in has expired. Please try again."), 403)

	try:
		config = get_sign_in_config()
		discovery = get_openid_configuration(config["sso_issuer"])
		key_name = config["social_login_key"]
		client_id = get_oauth_keys(key_name)["client_id"]
		auth_url_data = frappe.db.get_value("Social Login Key", key_name, "auth_url_data")
		redirect_uri = get_redirect_uri(key_name)
	except SSONotConfiguredError, ValueError, requests.RequestException:
		frappe.log_error(title="Single sign-on could not start")
		return _show_failure(_("Single sign-on is not available right now. Please try again later."), 502)

	binding = frappe.generate_hash(length=32)
	nonce = frappe.generate_hash(length=32)
	code_verifier = frappe.generate_hash(length=64)

	frappe.cache.set_value(
		f"{FLOW_CACHE_PREFIX}:{state}",
		{"binding": _hash_binding(binding), "nonce": nonce, "code_verifier": code_verifier},
		expires_in_sec=FLOW_LIFETIME_SECONDS,
	)
	# One cookie per state, so two tabs signing in at once do not refuse each other.
	frappe.local.cookie_manager.set_cookie(
		f"{FLOW_COOKIE_PREFIX}{state}", binding, max_age=FLOW_LIFETIME_SECONDS, httponly=True
	)

	params = {"scope": DEFAULT_SCOPE, **json.loads(auth_url_data or "{}")}
	params.update(
		{
			"response_type": "code",
			"client_id": client_id,
			"redirect_uri": redirect_uri,
			"state": state,
			"nonce": nonce,
			"code_challenge": make_code_challenge(code_verifier),
			"code_challenge_method": "S256",
		}
	)
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = f"{discovery['authorization_endpoint']}?{urlencode(params)}"


@frappe.whitelist(allow_guest=True)
def handle_callback(code: str | None = None, state: str | None = None, error: str | None = None):
	"""Completes the sign-in the identity provider sends back.

	Text from the request, the token or an exception never reaches the page: this endpoint is open
	to guests and Frappe's message page does not escape what it is given.
	"""
	flow = _take_flow(state)
	if not flow:
		log_audit_event(
			event_type="Session Refused",
			status="Refused",
			details={"reason": "Callback without a matching state and browser"},
			persist=False,
		)
		return _show_failure(_("Your sign-in has expired. Please try again."), 403)

	redirect_to = consume_oauth_state(state)
	if redirect_to is None:
		return _show_failure(_("Your sign-in has expired. Please try again."), 403)

	if error or not code:
		return _refuse_callback(
			_("The identity provider did not complete your sign-in. Please try again."),
			{"reason": "Identity provider returned no code", "error": (error or "")[:100]},
		)

	try:
		config = get_sign_in_config()
		key_name = config["social_login_key"]
		issuer = config["sso_issuer"]
		discovery = get_openid_configuration(issuer)
		keys = get_oauth_keys(key_name)
		tokens = exchange_code(
			# From the pinned issuer's discovery, not the Social Login Key a System Manager can edit.
			discovery["token_endpoint"],
			code,
			get_redirect_uri(key_name),
			keys["client_id"],
			keys["client_secret"],
			flow["code_verifier"],
		)
	except SSONotConfiguredError, ValueError, requests.RequestException:
		frappe.log_error(title="Single sign-on token exchange failed")
		return _show_failure(_("Single sign-on is not available right now. Please try again later."), 502)

	try:
		claims = verify_id_token(
			tokens.get("id_token") or "",
			discovery["jwks_uri"],
			issuer,
			keys["client_id"],
			flow["nonce"],
		)
		user = find_or_bind_user(claims, key_name, config["idp_type"])
	except (jwt.PyJWTError, ValueError) as e:
		return _refuse_callback(
			_("Your sign-in could not be verified. Please try again."),
			{"reason": "ID token verification failed", "error_type": type(e).__name__},
		)
	except SignInRefused as e:
		# find_or_bind_user logged the refusal and wrote nothing else.
		_commit_log()
		return _show_failure(str(e), 403)

	frappe.flags.oidc_session_authorized = True
	frappe.local.login_manager.login_as(user, session_end=_get_session_end(config["session_max_hours"]))
	log_audit_event(
		event_type="Login Success", status="Success", user=user, details={"iat": claims.get("iat")}
	)

	# nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit -- reviewed: Frappe rolls back a GET request, which would lose the session, the user and the log.
	frappe.db.commit()

	redirect_post_login(
		desk_user=frappe.local.response.get("message") == "Logged In",
		redirect_to=redirect_to or None,
		provider=key_name,
	)


def _get_session_end(max_hours: int) -> str:
	# With its zone: Frappe compares this with an aware now, and a naive value raises on every request.
	return (datetime.now(tz=UTC) + timedelta(hours=max_hours)).isoformat()


def _hash_binding(binding: str) -> str:
	return hashlib.sha256(binding.encode()).hexdigest()


def _take_flow(state: str | None) -> dict | None:
	"""Returns this state's flow if the browser started it, and removes it so it works only once.

	A request from any other browser leaves the flow in place, so it cannot cancel a real sign-in.
	"""
	if not state:
		return None

	cache_key = f"{FLOW_CACHE_PREFIX}:{state}"
	flow = frappe.cache.get_value(cache_key)
	cookie_name = f"{FLOW_COOKIE_PREFIX}{state}"
	binding = frappe.request.cookies.get(cookie_name)
	if not flow or not binding:
		return None
	if not hmac.compare_digest(_hash_binding(binding), flow["binding"]):
		return None

	frappe.cache.delete_value(cache_key)
	frappe.local.cookie_manager.delete_cookie(cookie_name)
	return flow


def _refuse_callback(message: str, details: dict) -> None:
	log_audit_event(event_type="Session Refused", status="Refused", details=details)
	_commit_log()
	_show_failure(message, 403)


def _commit_log() -> None:
	# nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit -- reviewed: Frappe rolls back a GET request, which would lose the refusal's log entry; nothing else was written.
	frappe.db.commit()


def _show_failure(message: str, http_status_code: int) -> None:
	frappe.respond_as_web_page(_("Single Sign-On Failed"), message, http_status_code=http_status_code)
