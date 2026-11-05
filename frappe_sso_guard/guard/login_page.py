# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from urllib.parse import urlencode

import frappe
import requests
from frappe.utils import get_url
from frappe.utils.oauth import get_oauth_keys

from frappe_sso_guard.guard.session_guard import (
	get_break_glass_user,
	is_bound_to_identity_provider,
	is_sso_forced,
)
from frappe_sso_guard.services.idp import (
	SSONotConfiguredError,
	get_openid_configuration,
	get_provider_key,
	get_sign_in_config,
)

LOGOUT_COOKIE = "sso_logout_pending"
LOGOUT_COOKIE_SECONDS = 300
# Only what the page shows: the session guard still refuses everyone but the break-glass account.
LOCAL_LOGIN_PARAM = "break-glass"
LOGOUT_COMMANDS = ("logout", "web_logout", "frappe.handler.logout", "frappe.handler.web_logout")


def redirect_login_page(context):
	"""update_website_context hook: takes /login to the identity provider instead of showing a form.

	It runs after Frappe's own login page has prepared the context, so the provider's link already
	carries a single-use state and the sanitised redirect-to.
	"""
	if not _is_login_page() or frappe.session.user != "Guest":
		return

	if frappe.request.cookies.get(LOGOUT_COOKIE):
		frappe.local.cookie_manager.delete_cookie(LOGOUT_COOKIE)
		if logout_url := _get_end_session_url():
			_redirect(logout_url)

	if not is_sso_forced():
		return

	if frappe.request.args.get(LOCAL_LOGIN_PARAM) and get_break_glass_user():
		return

	provider_key = get_provider_key()
	for provider in context.provider_logins or []:
		if provider["name"] == provider_key:
			_redirect(provider["auth_url"])


def remember_logout(login_manager):
	"""on_logout hook: the next /login goes through the identity provider's logout first.

	Frappe's logout is a POST answered in JSON, so it cannot redirect the browser itself, and the
	desk and frappe-ui apps go to /login after it. Without this the next visit signs straight back in.
	"""
	if not _is_own_logout():
		return
	if not frappe.db.get_single_value("SSO Identity Settings", "enable_single_logout"):
		return
	if is_bound_to_identity_provider(frappe.session.user):
		frappe.local.cookie_manager.set_cookie(
			LOGOUT_COOKIE, "1", max_age=LOGOUT_COOKIE_SECONDS, httponly=True
		)


def _is_login_page() -> bool:
	# The context's path is set only after this hook runs, and a page can render with no request.
	request = getattr(frappe.local, "request", None)
	return bool(request) and request.path.strip("/") == "login"


def _is_own_logout() -> bool:
	# User.save also runs on_logout, naming no one, when an administrator disables somebody else.
	# API v2 sets no cmd, so the method comes from the path there.
	request = getattr(frappe.local, "request", None)
	if not request:
		return False
	return (frappe.form_dict.get("cmd") or request.path.rpartition("/")[2]) in LOGOUT_COMMANDS


def _get_end_session_url() -> str | None:
	try:
		config = get_sign_in_config()
		endpoint = get_openid_configuration(config["sso_issuer"]).get("end_session_endpoint")
		client_id = get_oauth_keys(config["social_login_key"])["client_id"]
	except SSONotConfiguredError, ValueError, requests.RequestException:
		frappe.log_error(title="Single logout could not start")
		return None

	if not endpoint:
		return None
	params = {"client_id": client_id, "post_logout_redirect_uri": get_url("/login")}
	return f"{endpoint}?{urlencode(params)}"


def _redirect(location: str) -> None:
	frappe.flags.redirect_location = location
	# Not Frappe's default 301: a browser would keep it, and this link's state works only once.
	raise frappe.Redirect(302)
