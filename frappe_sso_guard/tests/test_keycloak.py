# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import html
import os
import re
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urljoin, urlparse

import frappe
import requests
from frappe.tests import IntegrationTestCase
from frappe.tests.test_api import make_request
from frappe.utils import get_test_client, get_url, now_datetime

from frappe_sso_guard import commands
from frappe_sso_guard.api import callback
from frappe_sso_guard.guard import login_page, session_guard
from frappe_sso_guard.services import idp
from frappe_sso_guard.tasks.reconciliation import reconcile_users
from frappe_sso_guard.tests.utils import remove_traces_of_deleted, remove_traces_of_deleted_users

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", commands.KEYCLOAK_DEFAULT_URL).rstrip("/")
REALM = "frappe-sso-guard-test"
ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"
PROVIDER_KEY = "test_sso_keycloak"
CALLBACK_PATH = "/api/method/frappe_sso_guard.api.callback.handle_callback"
START_PATH = "/api/method/frappe_sso_guard.api.callback.start"
# Not the realm file's addresses: a developer's own sign-ins through setup_keycloak created those.
ACTIVE = "test.sso.active@example.org"
DISABLED = "test.sso.disabled@example.org"
UNVERIFIED = "test.sso.unverified@example.org"
LEAVER = "test.sso.leaver@example.org"
USERS = (ACTIVE, DISABLED, UNVERIFIED, LEAVER)
MAX_REDIRECTS = 15


class Browser:
	"""Follows redirects and keeps cookies per host across Keycloak over HTTP and Frappe's application.

	It keeps a Secure cookie on plain HTTP, as browsers do for localhost and Keycloak expects, which is
	why this is not a requests.Session.
	"""

	def __init__(self):
		self.client = get_test_client(use_cookies=False)
		self.cookies: dict[str, dict[str, str]] = {}
		self.visited: list[str] = []

	def open(self, url, method="GET", data=None):
		"""Stops at Frappe's answer to the callback: where it sends the person next is not under test."""
		for _hop in range(MAX_REDIRECTS):
			self.visited.append(url)
			status, location, text = self._fetch(url, method, data)
			if location and not url.split("?")[0].endswith(CALLBACK_PATH):
				url, method, data = urljoin(url, location), "GET", None
				continue
			return frappe._dict(url=url, status=status, location=location, text=text)
		raise AssertionError(f"Too many redirects: {self.visited[-MAX_REDIRECTS:]}")

	def _fetch(self, url, method, data):
		parts = urlparse(url)
		host_cookies = self.cookies.setdefault(parts.netloc, {})
		headers = {"Cookie": "; ".join(f"{name}={value}" for name, value in host_cookies.items())}

		if url.startswith(KEYCLOAK_URL):
			response = requests.request(
				method, url, data=data, headers=headers, allow_redirects=False, timeout=30
			)
			set_cookies = response.raw.headers.getlist("Set-Cookie")
			status, location, text = response.status_code, response.headers.get("Location"), response.text
		else:
			target = self.client.get if method == "GET" else self.client.post
			path = f"{parts.path}?{parts.query}" if parts.query else parts.path
			kwargs = {"headers": headers, "base_url": f"{parts.scheme}://{parts.netloc}", "data": data}
			response = make_request(target=target, args=(path,), kwargs=kwargs)
			frappe.db.rollback()
			set_cookies = response.headers.getlist("Set-Cookie")
			status = response.status_code
			location, text = response.headers.get("Location"), response.get_data(as_text=True)

		self._keep_cookies(host_cookies, set_cookies)
		return status, location, text

	def _keep_cookies(self, host_cookies, set_cookies):
		for header in set_cookies:
			name, _, value = header.split(";")[0].partition("=")
			if not value or "Max-Age=0" in header or "1970" in header:
				host_cookies.pop(name, None)
			else:
				host_cookies[name] = value

	def submit(self, page, form_id, **fields):
		"""Posts one of Keycloak's forms as the page gives it, hidden fields included."""
		# Keycloak puts this id on the form at login and on a div around it at logout.
		form = re.search(rf'id="{form_id}".*?</form>', page.text, re.S)
		if not form:
			raise AssertionError(f"No form {form_id} on {page.url}: {page.text[:500]}")
		action = html.unescape(re.search(r'action="([^"]*)"', form.group(0)).group(1))
		hidden = {
			html.unescape(name): html.unescape(value)
			for name, value in re.findall(
				r'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"', form.group(0)
			)
		}
		return self.open(urljoin(page.url, action), "POST", {**hidden, **fields})

	def sign_in(self, site_url, username, password):
		page = self.open(f"{site_url}/login")
		return self.submit(page, "kc-form-login", username=username, password=password)

	def signed_in_user(self, site_url):
		page = self.open(f"{site_url}/api/method/frappe.auth.get_logged_user")
		return frappe.parse_json(page.text).get("message") if page.status == 200 else None

	def callback_url(self):
		return next(url for url in reversed(self.visited) if url.split("?")[0].endswith(CALLBACK_PATH))


class KeycloakAdmin:
	def __init__(self, password):
		self.password = password

	def _call(self, method, path, **kwargs):
		token = commands.get_keycloak_admin_token(KEYCLOAK_URL, self.password)
		response = requests.request(
			method,
			f"{KEYCLOAK_URL}/admin/realms/{REALM}{path}",
			headers={"Authorization": f"Bearer {token}"},
			timeout=30,
			**kwargs,
		)
		response.raise_for_status()
		return response

	def user_id(self, email):
		return self._call("GET", "/users", params={"email": email, "exact": "true"}).json()[0]["id"]

	def update_user(self, address, **fields):
		self._call("PUT", f"/users/{self.user_id(address)}", json=fields)

	def delete_user(self, email):
		self._call("DELETE", f"/users/{self.user_id(email)}")

	def delete_realm(self):
		self._call("DELETE", "")

	def remove_directory_role(self):
		account = self._call(
			"GET", "/users", params={"username": "service-account-frappe-sso-guard-directory"}
		)
		account_id = account.json()[0]["id"]
		clients = self._call("GET", "/clients", params={"clientId": "realm-management"}).json()
		client_id = clients[0]["id"]
		role = self._call("GET", f"/clients/{client_id}/roles/view-users").json()
		self._call("DELETE", f"/users/{account_id}/role-mappings/clients/{client_id}", json=[role])


class TestKeycloak(IntegrationTestCase):
	"""The whole sign-in against a real Keycloak. It needs one running and its admin password in
	KEYCLOAK_PASSWORD, so it skips in CI. docs/04 has how to run it.

	Frappe's requests run on their own connection, so what they read is committed and removed afterwards.
	"""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.admin_password = os.environ.get("KEYCLOAK_PASSWORD")
		if not cls.admin_password:
			raise unittest.SkipTest("KEYCLOAK_PASSWORD is not set")
		try:
			requests.get(f"{KEYCLOAK_URL}/realms/master", timeout=5).raise_for_status()
		except requests.RequestException as e:
			raise unittest.SkipTest(f"No Keycloak at {KEYCLOAK_URL}") from e

	def setUp(self):
		# Through the document: get_single_value turns an empty date into the year 1.
		settings = frappe.get_single("SSO Identity Settings")
		self.saved_settings = {
			field: settings.get(field)
			for field in (
				"social_login_key",
				"idp_type",
				"enable_single_logout",
				"session_max_hours",
				# Ending a real session commits, in Frappe's delete_session, so a rollback does not undo this.
				"last_reconciliation",
			)
		}
		self.site_url = get_url()
		self.started = now_datetime()
		self._cleanup()
		self.addCleanup(self._cleanup)

		realm = commands.load_keycloak_realm()
		realm["realm"] = REALM
		for user in realm["users"]:
			if user.get("email"):
				user["email"] = f"test.{user['email']}"
		self.secrets = commands.create_keycloak_realm(KEYCLOAK_URL, self.admin_password, realm, self.site_url)
		self.admin = KeycloakAdmin(self.admin_password)
		self.addCleanup(self.admin.delete_realm)

		frappe.get_doc(
			{
				"doctype": "Social Login Key",
				"provider_name": PROVIDER_KEY,
				"enable_social_login": 1,
				"client_id": self.secrets["client_id"],
				"client_secret": self.secrets["client_secret"],
				"base_url": ISSUER,
				"authorize_url": START_PATH,
				"access_token_url": f"{ISSUER}/protocol/openid-connect/token",
				"redirect_url": CALLBACK_PATH,
			}
		).insert(ignore_permissions=True)
		for email in USERS:
			frappe.get_doc(
				{"doctype": "User", "email": email, "first_name": "Synthetic", "send_welcome_email": 0}
			).insert(ignore_permissions=True)
		settings = frappe.get_single("SSO Identity Settings")
		settings.social_login_key = PROVIDER_KEY
		settings.idp_type = "Keycloak"
		settings.enable_single_logout = 1
		settings.session_max_hours = 2
		settings.save()
		frappe.db.commit()

		# The requests read the site config afresh, so the issuer reaches them through these.
		real_get_sso_config = idp.get_sso_config
		for patcher in (
			patch.object(idp, "get_sso_config", lambda: {**real_get_sso_config(), "sso_issuer": ISSUER}),
			patch.object(login_page, "is_sso_forced", return_value=True),
			patch.object(session_guard, "is_sso_forced", return_value=True),
			patch.object(frappe, "sendmail"),
			patch.object(frappe, "log_error"),
		):
			patcher.start()
			self.addCleanup(patcher.stop)

		self.browser = Browser()

	def _cleanup(self):
		frappe.db.rollback()
		for field, value in self.saved_settings.items():
			frappe.db.set_single_value("SSO Identity Settings", field, value)
		frappe.db.delete("SSO Identity Assignment Log", {"user": ("in", USERS)})
		# A refusal before Keycloak names anyone has no user, as when a broken sign-in fails this test.
		frappe.db.delete(
			"SSO Identity Assignment Log",
			{"user": ("is", "not set"), "event_type": "Session Refused", "creation": (">=", self.started)},
		)
		for email in USERS:
			frappe.delete_doc_if_exists("User", email, force=1)
		remove_traces_of_deleted_users(USERS)
		frappe.delete_doc_if_exists("Social Login Key", PROVIDER_KEY, force=1)
		remove_traces_of_deleted("Social Login Key", (PROVIDER_KEY,))
		frappe.cache.delete_value(f"oidc_discovery_{ISSUER}")
		frappe.db.commit()

	def _sign_in(self, username, browser=None):
		return (browser or self.browser).sign_in(self.site_url, username, self.secrets["user_password"])

	def _binding(self, email):
		return frappe.db.get_value(
			"User Social Login", {"parent": email, "parenttype": "User", "provider": PROVIDER_KEY}, "userid"
		)

	def _sign_in_as_new_browser(self, username):
		browser = Browser()
		page = self._sign_in(username, browser)
		self.assertEqual(page.status, 302, page.text[:300])
		return browser

	# Signing in

	def test_sign_in_binds_the_account_and_opens_a_session_that_ends_at_the_set_time(self):
		claims = []
		real_verify = callback.verify_id_token

		def recording_verify(*args):
			claims.append(real_verify(*args))
			return claims[-1]

		with patch.object(callback, "verify_id_token", recording_verify):
			page = self._sign_in("sso.active")

		self.assertEqual(page.status, 302, page.text[:300])
		self.assertEqual(self.browser.signed_in_user(self.site_url), ACTIVE)
		# Bound by Keycloak's identifier, not the email.
		self.assertEqual(self._binding(ACTIVE), self.admin.user_id(ACTIVE))
		self.assertEqual(claims[0]["iss"], ISSUER)
		self.assertIs(claims[0]["email_verified"], True)

		sessions = frappe.qb.DocType("Sessions")
		rows = (
			frappe.qb.from_(sessions)
			.select(sessions.sessiondata)
			.where(sessions.user == ACTIVE)
			.run(pluck=True)
		)
		session_end = frappe.parse_json(rows[0])["session_end"]
		remaining = datetime.fromisoformat(session_end) - datetime.now(tz=UTC)
		self.assertTrue(timedelta(hours=1, minutes=55) < remaining <= timedelta(hours=2), remaining)

	def test_sign_in_uses_pkce_and_a_nonce(self):
		self._sign_in("sso.active")
		authorize = next(url for url in self.browser.visited if "/openid-connect/auth" in url)
		params = parse_qs(urlparse(authorize).query)
		self.assertEqual(params["code_challenge_method"], ["S256"])
		self.assertTrue(params["nonce"][0])
		self.assertEqual(params["redirect_uri"], [f"{self.site_url}{CALLBACK_PATH}"])

	def test_realm_refuses_a_sign_in_without_pkce(self):
		"""Shows the realm file really demands it, so a passing sign-in above means something."""
		authorize = (
			f"{ISSUER}/protocol/openid-connect/auth?response_type=code&scope=openid"
			f"&client_id={self.secrets['client_id']}&redirect_uri={self.site_url}{CALLBACK_PATH}"
		)
		location = requests.get(authorize, allow_redirects=False, timeout=30).headers["Location"]
		self.assertIn("error=invalid_request", location)

	def test_second_sign_in_finds_the_person_by_identifier_after_their_email_changes(self):
		self._sign_in_as_new_browser("sso.active")
		self.admin.update_user(ACTIVE, email="test.sso.renamed@example.org", emailVerified=True)

		browser = self._sign_in_as_new_browser("sso.active")

		self.assertEqual(browser.signed_in_user(self.site_url), ACTIVE)
		self.assertTrue(
			frappe.db.exists("SSO Identity Assignment Log", {"event_type": "Email Changed", "user": ACTIVE})
		)

	# Refusals

	def test_wrong_password_stays_at_keycloak(self):
		page = self.browser.sign_in(self.site_url, "sso.active", "not-the-password")
		self.assertTrue(page.url.startswith(KEYCLOAK_URL), page.url)
		self.assertIsNone(self._binding(ACTIVE))

	def test_person_disabled_at_keycloak_cannot_sign_in(self):
		page = self._sign_in("sso.disabled")
		self.assertTrue(page.url.startswith(KEYCLOAK_URL), page.url)
		self.assertIn("disabled", page.text.lower())
		self.assertIsNone(self._binding(DISABLED))
		self.assertFalse(frappe.db.exists("Sessions", {"user": DISABLED}))

	def test_unverified_email_is_not_bound(self):
		page = self._sign_in("sso.unverified")
		self.assertEqual(page.status, 403, page.text[:300])
		self.assertIsNone(self._binding(UNVERIFIED))
		self.assertFalse(frappe.db.exists("Sessions", {"user": UNVERIFIED}))

	def test_a_callback_cannot_be_replayed(self):
		self.assertEqual(self._sign_in("sso.active").status, 302)
		replay = self.browser.open(self.browser.callback_url())
		self.assertEqual(replay.status, 403, replay.text[:300])

	def test_a_callback_from_another_browser_is_refused(self):
		page = self.browser.open(f"{self.site_url}/login")
		# Stopped before the form: this browser started the sign-in, and another finishes it.
		other = Browser()
		other.cookies[urlparse(KEYCLOAK_URL).netloc] = self.browser.cookies[urlparse(KEYCLOAK_URL).netloc]
		finished = other.submit(
			page, "kc-form-login", username="sso.active", password=self.secrets["user_password"]
		)
		self.assertEqual(finished.status, 403, finished.text[:300])
		self.assertIsNone(self._binding(ACTIVE))

	# Logging out

	def _log_out(self):
		host_cookies = self.browser.cookies[urlparse(self.site_url).netloc]
		self.browser.open(f"{self.site_url}/api/method/logout", "POST", {})
		return host_cookies

	def test_logout_ends_the_keycloak_session_too(self):
		self._sign_in("sso.active")
		self._log_out()
		self.assertNotEqual(self.browser.signed_in_user(self.site_url), ACTIVE)

		page = self.browser.open(f"{self.site_url}/login")
		# Keycloak asks first when the request carries no ID token, and this app does not keep one.
		self.assertIn("/openid-connect/logout", page.url)
		page = self.browser.submit(page, "kc-logout-confirm", confirmLogout="Logout")

		# It came back through /login to Keycloak's form: nothing signed the person straight back in.
		self.assertIn('id="kc-form-login"', page.text, page.url)
		self.assertNotEqual(self.browser.signed_in_user(self.site_url), ACTIVE)

	def test_with_single_logout_off_the_next_visit_signs_straight_back_in(self):
		frappe.db.set_single_value("SSO Identity Settings", "enable_single_logout", 0)
		frappe.db.commit()
		self._sign_in("sso.active")
		self._log_out()

		page = self.browser.open(f"{self.site_url}/login")

		self.assertEqual(page.status, 302, page.text[:300])
		self.assertEqual(self.browser.signed_in_user(self.site_url), ACTIVE)

	# Reconciliation

	def _start_directory_conf(self):
		conf = {
			"sso_directory_client_id": self.secrets["directory_client_id"],
			"sso_directory_client_secret": self.secrets["directory_client_secret"],
		}
		patcher = patch.dict(frappe.conf, conf)
		patcher.start()
		self.addCleanup(patcher.stop)

	def _bind_three_people(self):
		self.admin.update_user(UNVERIFIED, emailVerified=True)
		for username in ("sso.active", "sso.leaver", "sso.unverified"):
			self._sign_in_as_new_browser(username)

	def test_reconciliation_disables_those_disabled_or_removed_at_keycloak(self):
		self._bind_three_people()
		self.admin.update_user(LEAVER, enabled=False)
		self.admin.delete_user(UNVERIFIED)
		self._start_directory_conf()

		summary = reconcile_users()

		self.assertEqual((summary["checked"], summary["disabled"]), (3, 2), summary)
		self.assertTrue(frappe.db.get_value("User", ACTIVE, "enabled"))
		self.assertFalse(frappe.db.get_value("User", LEAVER, "enabled"))
		self.assertFalse(frappe.db.get_value("User", UNVERIFIED, "enabled"))
		self.assertFalse(frappe.db.exists("Sessions", {"user": LEAVER}))
		frappe.db.rollback()

	def test_reconciliation_without_the_directory_role_disables_nobody(self):
		self._bind_three_people()
		self.admin.update_user(LEAVER, enabled=False)
		self.admin.remove_directory_role()
		self._start_directory_conf()

		summary = reconcile_users()

		self.assertEqual(summary["disabled"], 0, summary)
		self.assertTrue(frappe.db.get_value("User", LEAVER, "enabled"))
		frappe.db.rollback()
