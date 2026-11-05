# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import frappe
from frappe.tests import IntegrationTestCase
from frappe.tests.test_api import make_request
from frappe.utils import get_test_client
from frappe.utils.password import update_password

from frappe_sso_guard.guard import login_page, session_guard
from frappe_sso_guard.guard.login_page import LOGOUT_COOKIE

PROVIDER_KEY = "test_sso_login_page"
ISSUER = "https://idp.example.org/realms/test"
END_SESSION = f"{ISSUER}/logout"
USER = "sso.login.page@example.org"
BREAK_GLASS = "sso.login.page.glass@example.org"
START_PATH = "/api/method/frappe_sso_guard.api.callback.start"


def _forced(forced):
	return (
		patch.object(login_page, "is_sso_forced", return_value=forced),
		patch.object(session_guard, "is_sso_forced", return_value=forced),
	)


class TestLoginPage(IntegrationTestCase):
	"""Whole requests through Frappe's application. They run on their own connection, so what they read
	is committed here and removed afterwards."""

	def setUp(self):
		# These requests see only what is committed, so the developer's own settings are put back after.
		self.saved_settings = {
			field: frappe.db.get_single_value("SSO Identity Settings", field)
			for field in ("social_login_key", "enable_single_logout")
		}
		self._cleanup()
		self.addCleanup(self._cleanup)
		frappe.get_doc(
			{
				"doctype": "Social Login Key",
				"provider_name": PROVIDER_KEY,
				"enable_social_login": 1,
				"client_id": "client",
				"client_secret": "synthetic-test-secret",
				"base_url": "https://idp.example.org",
				"authorize_url": START_PATH,
				"access_token_url": "https://idp.example.org/token",
				"redirect_url": "/api/method/frappe_sso_guard.api.callback.handle_callback",
			}
		).insert(ignore_permissions=True)
		for email, roles in ((USER, []), (BREAK_GLASS, [{"role": "System Manager"}])):
			frappe.get_doc(
				{
					"doctype": "User",
					"email": email,
					"first_name": "Synthetic",
					"send_welcome_email": 0,
					"roles": roles,
				}
			).insert(ignore_permissions=True)
		settings = frappe.get_single("SSO Identity Settings")
		settings.social_login_key = PROVIDER_KEY
		settings.enable_single_logout = 1
		settings.save()
		frappe.cache.set_value(
			f"oidc_discovery_{ISSUER}",
			{
				"issuer": ISSUER,
				"authorization_endpoint": f"{ISSUER}/authorize",
				"token_endpoint": f"{ISSUER}/token",
				"jwks_uri": f"{ISSUER}/certs",
				"end_session_endpoint": END_SESSION,
			},
		)
		frappe.db.commit()
		self.client = get_test_client(use_cookies=False)
		# The requests run on their own thread, with their own copy of the site config.
		config = {"sso_issuer": ISSUER, "social_login_key": PROVIDER_KEY}
		for patcher in (
			patch.object(login_page, "get_sign_in_config", return_value=config),
			patch.object(frappe, "sendmail"),
		):
			patcher.start()
			self.addCleanup(patcher.stop)

	def _cleanup(self):
		frappe.db.rollback()
		for field, value in self.saved_settings.items():
			frappe.db.set_single_value("SSO Identity Settings", field, value)
		frappe.db.delete("SSO Identity Assignment Log", {"user": ("in", (USER, BREAK_GLASS))})
		frappe.db.delete("Error Log", {"method": "Single logout could not start"})
		for email in (USER, BREAK_GLASS):
			frappe.delete_doc_if_exists("User", email, force=1)
		frappe.delete_doc_if_exists("Social Login Key", PROVIDER_KEY, force=1)
		frappe.cache.delete_value(f"oidc_discovery_{ISSUER}")
		frappe.db.commit()

	def _start_patches(self, *patches):
		for each in patches:
			each.start()
			self.addCleanup(each.stop)

	def _get_login(self, query="", cookie=None):
		headers = {"Cookie": cookie} if cookie else {}
		response = make_request(target=self.client.get, args=(f"/login{query}",), kwargs={"headers": headers})
		frappe.db.rollback()
		return response

	def test_forced_sends_login_to_the_identity_provider_with_a_state(self):
		self._start_patches(*_forced(True))
		response = self._get_login("?redirect-to=/desk/case")

		self.assertEqual(response.status_code, 302)
		location = urlparse(response.headers["Location"])
		self.assertEqual(location.path, START_PATH)
		state = parse_qs(location.query)["state"][0]
		self.assertTrue(frappe.cache.get_value(f"frappe_oauth_login:{state}").endswith("/desk/case"))

	def test_not_forced_shows_the_login_form(self):
		self._start_patches(*_forced(False))
		self.assertEqual(self._get_login().status_code, 200)

	def test_break_glass_address_shows_the_form_only_with_an_account_named(self):
		self._start_patches(
			*_forced(True), patch.object(login_page, "get_break_glass_user", return_value=None)
		)
		self.assertEqual(self._get_login("?break-glass=1").status_code, 302)

		self._start_patches(patch.object(login_page, "get_break_glass_user", return_value=BREAK_GLASS))
		self.assertEqual(self._get_login("?break-glass=1").status_code, 200)
		self.assertEqual(self._get_login().status_code, 302)

	def test_site_without_a_provider_shows_the_form_instead_of_looping(self):
		self._start_patches(*_forced(True))
		frappe.db.set_single_value("SSO Identity Settings", "social_login_key", None)
		frappe.db.commit()
		self.assertEqual(self._get_login().status_code, 200)

	def _logout_as(self, user, command="logout"):
		frappe.set_user("Administrator")
		frappe.local.form_dict = frappe._dict(cmd=command)
		frappe.local.request = frappe._dict(path=f"/api/method/{command}")
		frappe.local.cookie_manager = frappe.auth.CookieManager()
		frappe.session.user = user
		login_page.remember_logout(None)
		return frappe.local.cookie_manager.cookies

	def _bind(self, user):
		frappe.get_doc(
			{
				"doctype": "User Social Login",
				"parent": user,
				"parenttype": "User",
				"parentfield": "social_logins",
				"provider": PROVIDER_KEY,
				"userid": "login-page-user",
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()

	def _restore_request(self):
		frappe.set_user("Administrator")
		frappe.local.request = None

	def test_logout_of_a_bound_user_remembers_to_end_the_provider_session(self):
		self._bind(USER)
		self.addCleanup(self._restore_request)
		self.assertIn(LOGOUT_COOKIE, self._logout_as(USER))

	def test_logout_of_a_user_not_bound_does_not(self):
		self.addCleanup(self._restore_request)
		self.assertNotIn(LOGOUT_COOKIE, self._logout_as(BREAK_GLASS))

	def test_an_administrator_disabling_someone_does_not(self):
		self._bind(USER)
		self.addCleanup(self._restore_request)
		self.assertNotIn(LOGOUT_COOKIE, self._logout_as(USER, "frappe.desk.form.save.savedocs"))

	def test_single_logout_switched_off_does_not(self):
		self._bind(USER)
		frappe.db.set_single_value("SSO Identity Settings", "enable_single_logout", 0)
		frappe.db.commit()
		self.addCleanup(self._restore_request)
		self.assertNotIn(LOGOUT_COOKIE, self._logout_as(USER))

	def test_pending_logout_goes_to_the_provider_once_then_to_sign_in(self):
		self._start_patches(*_forced(True))

		response = self._get_login(cookie=f"{LOGOUT_COOKIE}=1")
		self.assertEqual(response.status_code, 302)
		location = urlparse(response.headers["Location"])
		self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", END_SESSION)
		params = parse_qs(location.query)
		self.assertEqual(params["client_id"], ["client"])
		self.assertTrue(params["post_logout_redirect_uri"][0].endswith("/login"))
		# The browser is told to forget it, or every later visit would log out again.
		deletion = [c for c in response.headers.getlist("Set-Cookie") if c.startswith(f"{LOGOUT_COOKIE}=")]
		self.assertTrue(deletion and deletion[0].startswith(f"{LOGOUT_COOKIE}=;"), deletion)

		self.assertEqual(urlparse(self._get_login().headers["Location"]).path, START_PATH)

	def test_provider_with_no_logout_endpoint_goes_on_to_sign_in(self):
		self._start_patches(*_forced(True))
		frappe.cache.set_value(
			f"oidc_discovery_{ISSUER}",
			{
				"issuer": ISSUER,
				"authorization_endpoint": f"{ISSUER}/authorize",
				"token_endpoint": f"{ISSUER}/token",
				"jwks_uri": f"{ISSUER}/certs",
			},
		)
		location = self._get_login(cookie=f"{LOGOUT_COOKIE}=1").headers["Location"]
		self.assertEqual(urlparse(location).path, START_PATH)

	def _sid_of_password_login(self, email):
		password = frappe.generate_hash()
		update_password(email, password)
		frappe.db.commit()
		response = make_request(
			target=self.client.post,
			args=("/api/method/login",),
			kwargs={"json": {"usr": email, "pwd": password}},
		)
		frappe.db.rollback()
		self.assertEqual(response.status_code, 200)
		cookies = response.headers.getlist("Set-Cookie")
		return next(c.split(";")[0].split("=", 1)[1] for c in cookies if c.startswith("sid="))

	def _post_logout(self, sid):
		response = make_request(
			target=self.client.post,
			args=("/api/method/logout",),
			kwargs={"headers": {"Cookie": f"sid={sid}"}},
		)
		frappe.db.rollback()
		self.assertEqual(response.status_code, 200)
		return response.headers.getlist("Set-Cookie")

	def test_a_real_logout_request_of_a_bound_user_sets_the_cookie(self):
		self._start_patches(*_forced(False))
		sid = self._sid_of_password_login(USER)
		self._bind(USER)
		self.assertTrue(any(c.startswith(f"{LOGOUT_COOKIE}=1") for c in self._post_logout(sid)))

	def test_a_real_logout_request_of_a_user_not_bound_sets_no_cookie(self):
		self._start_patches(*_forced(False))
		sid = self._sid_of_password_login(USER)
		self.assertFalse(any(c.startswith(f"{LOGOUT_COOKIE}=") for c in self._post_logout(sid)))
