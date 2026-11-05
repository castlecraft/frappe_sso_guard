# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from unittest.mock import patch

import frappe
from frappe.auth import LoginManager
from frappe.tests import IntegrationTestCase
from frappe.tests.test_api import make_request
from frappe.utils import get_test_client, set_request
from frappe.utils.password import check_password, update_password

from frappe_sso_guard.guard import password_guard, session_guard

USER = "sso.path.user@example.com"
BREAK_GLASS = "sso.path.break.glass@example.com"
UPDATE_PASSWORD = "/api/method/frappe.core.doctype.user.user.update_password"


def _break_glass(user):
	"""The site config is per thread, and a whole request runs on its own, so the reader is patched."""
	return patch.object(session_guard, "get_break_glass_user", return_value=user)


def _not_an_administrator():
	return patch.object(session_guard, "holds_admin_role", return_value=False)


def _force_sso(forced):
	"""force_sso is read from the site's file on every request, so the switch is patched instead."""
	return (
		patch.object(session_guard, "is_sso_forced", return_value=forced),
		patch.object(password_guard, "is_sso_forced", return_value=forced),
	)


class SignInPathsTestCase(IntegrationTestCase):
	def _start_patches(self, *patches):
		for each in patches:
			each.start()
			self.addCleanup(each.stop)

	def _insert_user(self, email):
		return frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "Synthetic",
				"send_welcome_email": 0,
				"roles": [{"role": "System Manager"}],
			}
		).insert()


class TestRequests(SignInPathsTestCase):
	"""Whole requests through Frappe's application, as only those run the login inside HTTPRequest().

	The request runs on its own thread and connection, so what it reads is committed here and removed
	afterwards.
	"""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.client = get_test_client(use_cookies=False)

	def setUp(self):
		self._cleanup_records()
		self.addCleanup(self._cleanup_records)
		self.passwords = {}
		for email in (USER, BREAK_GLASS):
			self._insert_user(email)
			self.passwords[email] = frappe.generate_hash()
			update_password(email, self.passwords[email])
		frappe.db.commit()
		self._start_patches(patch.object(frappe, "sendmail"), _break_glass(BREAK_GLASS))

	def _cleanup_records(self):
		frappe.db.rollback()
		frappe.db.delete("SSO Identity Assignment Log", {"user": ("in", (USER, BREAK_GLASS))})
		for email in (USER, BREAK_GLASS):
			frappe.delete_doc_if_exists("User", email, force=1)
		frappe.db.commit()

	def _post(self, path, **data):
		response = make_request(target=self.client.post, args=(path,), kwargs={"json": data})
		frappe.db.rollback()
		return response

	def _login(self, email):
		return self._post("/api/method/login", usr=email, pwd=self.passwords[email])

	def _logged(self, event_type, user):
		return frappe.db.exists("SSO Identity Assignment Log", {"event_type": event_type, "user": user})

	def _reset_key(self, email):
		key = frappe.get_doc("User", email)._reset_password().split("key=")[1]
		frappe.db.commit()
		return key

	def test_forced_refuses_a_password_login_and_keeps_the_log(self):
		# The guard skips its commit in a test, and the commit is what this test is checking.
		self._start_patches(*_force_sso(True), patch.object(frappe, "in_test", False))
		self.assertEqual(self._login(USER).status_code, 403)
		self.assertTrue(self._logged("Session Refused", USER))

	def test_forced_lets_the_break_glass_account_in_and_logs_it(self):
		self._start_patches(*_force_sso(True))
		response = self._login(BREAK_GLASS)
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		self.assertTrue(self._logged("Break-Glass Login", BREAK_GLASS))

	def test_not_forced_refuses_an_administrator_a_password_login(self):
		# The guard skips its commit in a test, and the commit is what keeps the log.
		self._start_patches(*_force_sso(False), patch.object(frappe, "in_test", False))
		self.assertEqual(self._login(USER).status_code, 403)
		self.assertTrue(self._logged("Session Refused", USER))

	def test_not_forced_lets_the_break_glass_account_in(self):
		self._start_patches(*_force_sso(False))
		self.assertEqual(self._login(BREAK_GLASS).status_code, 200)
		self.assertTrue(self._logged("Break-Glass Login", BREAK_GLASS))

	def test_not_forced_allows_a_password_login(self):
		self._start_patches(*_force_sso(False), _not_an_administrator())
		self.assertEqual(self._login(USER).status_code, 200)

	def test_forced_keeps_the_old_password_when_a_reset_key_is_used(self):
		self._start_patches(*_force_sso(True))
		new_password = frappe.generate_hash()

		response = self._post(UPDATE_PASSWORD, new_password=new_password, key=self._reset_key(USER))

		self.assertEqual(response.status_code, 404)
		self.assertEqual(check_password(USER, self.passwords[USER]), USER)
		with self.assertRaises(frappe.AuthenticationError):
			check_password(USER, new_password)

	def test_forced_lets_the_break_glass_account_use_a_reset_key(self):
		self._start_patches(*_force_sso(True))
		new_password = frappe.generate_hash()

		response = self._post(UPDATE_PASSWORD, new_password=new_password, key=self._reset_key(BREAK_GLASS))

		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		self.assertEqual(check_password(BREAK_GLASS, new_password), BREAK_GLASS)

	def test_not_forced_allows_a_reset_key(self):
		self._start_patches(*_force_sso(False), _not_an_administrator())
		new_password = frappe.generate_hash()

		response = self._post(UPDATE_PASSWORD, new_password=new_password, key=self._reset_key(USER))

		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		self.assertEqual(check_password(USER, new_password), USER)


class TestPasswordGuard(SignInPathsTestCase):
	def setUp(self):
		self.user = self._insert_user(USER)
		self.addCleanup(frappe.db.rollback)
		self._start_patches(
			_break_glass(None),
			patch.object(frappe, "sendmail"),
			patch.object(frappe.db, "commit"),
		)

	def _set_web_request(self, is_web):
		self._start_patches(patch.object(password_guard, "is_web_request", return_value=is_web))

	def _new_password(self):
		self.user.new_password = frappe.generate_hash()
		self.user.save()

	def test_forced_refuses_a_password_from_the_user_form(self):
		self._start_patches(*_force_sso(True))
		self._set_web_request(True)
		with self.assertRaises(frappe.PermissionError):
			self._new_password()

	def test_forced_allows_the_break_glass_account_a_password_from_the_form(self):
		self._start_patches(*_force_sso(True))
		self._set_web_request(True)
		self._start_patches(_break_glass(self.user.name))
		self._new_password()

	def test_forced_allows_a_password_from_a_bench_command(self):
		self._start_patches(*_force_sso(True))
		self._set_web_request(False)
		self._new_password()

	def test_not_forced_allows_a_password_from_the_user_form(self):
		self._start_patches(*_force_sso(False), _not_an_administrator())
		self._set_web_request(True)
		self._new_password()

	def test_forced_refuses_a_reset_request_silently(self):
		self._start_patches(*_force_sso(True))
		with self.assertRaises(frappe.DoesNotExistError):
			self.user.validate_reset_password()

	def test_forced_allows_the_break_glass_account_a_reset_request(self):
		self._start_patches(*_force_sso(True))
		self._start_patches(_break_glass(self.user.name))
		self.user.validate_reset_password()

	def test_not_forced_allows_a_reset_request(self):
		self._start_patches(*_force_sso(False), _not_an_administrator())
		self.user.validate_reset_password()

	def test_welcome_email_follows_the_switch(self):
		for forced, expected in ((True, 0), (False, 1)):
			with self.subTest(forced=forced):
				patches = _force_sso(forced)
				for each in patches:
					each.start()
				self.user.send_welcome_email = 1
				password_guard.before_validate_user(self.user)
				for each in patches:
					each.stop()
				self.assertEqual(self.user.send_welcome_email, expected)

	def test_invitations_follow_the_switch(self):
		invitation = frappe._dict(doctype="User Invitation")
		with _force_sso(True)[1], self.assertRaises(frappe.PermissionError):
			password_guard.before_insert_user_invitation(invitation)
		with _force_sso(False)[1]:
			password_guard.before_insert_user_invitation(invitation)

	def test_hooks_are_registered(self):
		hooks = frappe.get_doc_hooks()
		self.assertIn(
			"frappe_sso_guard.guard.password_guard.validate_reset_password",
			hooks["User"]["validate_reset_password"],
		)
		self.assertIn(
			"frappe_sso_guard.guard.password_guard.before_insert_user_invitation",
			hooks["User Invitation"]["before_insert"],
		)


class TestLoginAsPaths(SignInPathsTestCase):
	"""The email link, a reset key and an invitation all end in login_as, which reaches the guard."""

	def setUp(self):
		self.user = self._insert_user(USER).name
		self._start_patches(_break_glass(None))
		self.addCleanup(frappe.db.rollback)
		self.addCleanup(setattr, frappe.local, "request_ip", frappe.local.request_ip)
		self.addCleanup(setattr, frappe.local, "request", getattr(frappe.local, "request", None))
		self.addCleanup(frappe.set_user, "Administrator")
		self._start_patches(
			patch.object(frappe, "sendmail"),
			patch.object(frappe.db, "commit"),
			# Past the guard, only the guard's answer matters: no session has to open for real.
			patch.object(LoginManager, "make_session"),
			patch.object(LoginManager, "setup_boot_cache"),
			patch.object(LoginManager, "set_user_info"),
		)
		frappe.local.request_ip = "192.0.2.1"
		set_request(method="GET", path="/")
		frappe.local.login_manager = LoginManager()

	def test_forced_refuses_a_session_from_a_web_request(self):
		self._start_patches(*_force_sso(True))
		with self.assertRaises(frappe.PermissionError):
			frappe.local.login_manager.login_as(self.user)

	def test_not_forced_allows_it(self):
		self._start_patches(*_force_sso(False), _not_an_administrator())
		frappe.local.login_manager.login_as(self.user)

	def test_bench_browse_is_allowed_while_forced(self):
		self._start_patches(*_force_sso(True))
		frappe.local.request_ip = None
		frappe.local.login_manager.login_as(self.user)
