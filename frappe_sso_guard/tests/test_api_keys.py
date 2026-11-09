# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from unittest.mock import patch

import frappe
from frappe.core.doctype.user.user import generate_keys
from frappe.tests import IntegrationTestCase
from frappe.utils import set_request

from frappe_sso_guard.guard import api_key_guard, session_guard
from frappe_sso_guard.guard.api_key_guard import API_KEY_ALLOWED_FIELD
from frappe_sso_guard.services.directory import ACCOUNT_ACTIVE, ACCOUNT_REMOVED, DirectoryError
from frappe_sso_guard.tasks import api_keys

USER = "sso.key.holder@example.org"
PROVIDER_KEY = "test_sso_api_keys"


class ApiKeyTestCase(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		self.addCleanup(frappe.db.rollback)
		frappe.get_doc(
			{"doctype": "User", "email": USER, "first_name": "Synthetic", "send_welcome_email": 0}
		).insert(ignore_permissions=True)

	def _flag(self, **values):
		frappe.db.set_value("User", USER, {API_KEY_ALLOWED_FIELD: 1, "restrict_ip": "192.0.2.0/24", **values})

	def _logged(self, event_type):
		return frappe.db.exists("SSO Identity Assignment Log", {"event_type": event_type, "user": USER})


class TestGuard(ApiKeyTestCase):
	def setUp(self):
		super().setUp()
		for patcher in (
			patch.object(api_key_guard, "is_sso_forced", return_value=True),
			patch.object(api_key_guard, "is_web_request", return_value=True),
		):
			patcher.start()
			self.addCleanup(patcher.stop)

	def test_key_refused_for_a_user_not_flagged(self):
		frappe.db.set_value("User", USER, "restrict_ip", "192.0.2.0/24")
		with self.assertRaises(frappe.PermissionError):
			generate_keys(USER)
		self.assertFalse(self._logged("API Key Created"))

	def test_key_refused_without_restrict_ip(self):
		self._flag(restrict_ip=None)
		with self.assertRaises(frappe.PermissionError):
			generate_keys(USER)

	def test_key_refused_for_an_administrative_role(self):
		self._flag()
		frappe.get_doc("User", USER).add_roles("System Manager")
		with self.assertRaises(frappe.PermissionError):
			generate_keys(USER)

	def test_key_created_for_a_flagged_user_and_logged(self):
		self._flag()
		keys = generate_keys(USER)
		self.assertTrue(keys["api_secret"])
		self.assertTrue(self._logged("API Key Created"))

	def test_administrative_role_refused_to_a_key_holder(self):
		self._flag()
		generate_keys(USER)
		with self.assertRaises(frappe.PermissionError):
			frappe.get_doc("User", USER).add_roles("System Manager")

	def test_removing_restrict_ip_from_a_key_holder_is_refused(self):
		self._flag()
		generate_keys(USER)
		doc = frappe.get_doc("User", USER)
		doc.restrict_ip = None
		with self.assertRaises(frappe.PermissionError):
			doc.save()

	def test_an_earlier_key_holder_can_still_save_their_profile(self):
		frappe.db.set_value("User", USER, "api_key", "synthetic-key")
		doc = frappe.get_doc("User", USER)
		doc.bio = "Synthetic"
		doc.save()

	def test_user_without_a_key_is_left_alone(self):
		doc = frappe.get_doc("User", USER)
		doc.bio = "Synthetic"
		doc.save()

	def test_flag_cannot_be_set_by_the_user_themselves(self):
		self.assertEqual(frappe.get_meta("User").get_field(API_KEY_ALLOWED_FIELD).permlevel, 1)


class TestGuardOff(ApiKeyTestCase):
	def test_key_allowed_when_sso_is_not_forced_and_still_logged(self):
		with patch.object(api_key_guard, "is_sso_forced", return_value=False):
			generate_keys(USER)
		self.assertTrue(self._logged("API Key Created"))

	def test_key_allowed_from_a_bench_command_and_still_logged(self):
		with (
			patch.object(api_key_guard, "is_sso_forced", return_value=True),
			patch.object(api_key_guard, "is_web_request", return_value=False),
		):
			generate_keys(USER)
		self.assertTrue(self._logged("API Key Created"))


class TestDailyCheck(ApiKeyTestCase):
	def setUp(self):
		super().setUp()
		frappe.db.set_value("User", USER, "api_key", "synthetic-key")
		frappe.db.set_single_value("SSO Identity Settings", "social_login_key", None)
		frappe.db.set_single_value("SSO Identity Settings", "admin_notification_emails", "")

	def _alerts(self):
		rows = frappe.get_all(
			"SSO Identity Assignment Log", {"event_type": "API Key Alert", "user": USER}, pluck="details"
		)
		return " ".join(rows)

	def test_reports_each_broken_rule(self):
		frappe.get_doc("User", USER).add_roles("System Manager")
		api_keys.verify_active_api_key_users()
		alerts = self._alerts()
		self.assertIn("without being flagged", alerts)
		self.assertIn("without Restrict IP", alerts)
		self.assertIn("administrative role", alerts)

	def test_reports_nothing_for_a_holder_within_the_rules(self):
		self._flag()
		api_keys.verify_active_api_key_users()
		self.assertEqual(self._alerts(), "")

	def _bind(self):
		frappe.get_doc(
			{
				"doctype": "Social Login Key",
				"provider_name": PROVIDER_KEY,
				"client_id": "client",
				"client_secret": "synthetic-test-secret",
				"base_url": "https://idp.example.org",
				"authorize_url": "/authorize",
				"access_token_url": "/token",
				"redirect_url": "/callback",
			}
		).insert(ignore_permissions=True)
		frappe.db.set_single_value("SSO Identity Settings", "social_login_key", PROVIDER_KEY)
		frappe.get_doc(
			{
				"doctype": "User Social Login",
				"parent": USER,
				"parenttype": "User",
				"parentfield": "social_logins",
				"provider": PROVIDER_KEY,
				"userid": "key-holder",
			}
		).insert(ignore_permissions=True)
		self._flag()

	def _run_with_directory(self, status=ACCOUNT_ACTIVE, error=None):
		with (
			patch.object(
				api_keys, "get_sign_in_config", return_value={"idp_type": "Keycloak", "sso_issuer": "i"}
			),
			patch.object(api_keys, "DirectoryClient") as client,
			patch("frappe_sso_guard.tasks.reconciliation.clear_sessions"),
		):
			client.return_value.get_account_status.return_value = status
			client.return_value.get_account_status.side_effect = error
			api_keys.verify_active_api_key_users()

	def test_holder_gone_from_the_identity_provider_is_disabled(self):
		self._bind()
		self._run_with_directory(ACCOUNT_REMOVED)
		self.assertEqual(frappe.db.get_value("User", USER, "enabled"), 0)
		self.assertTrue(self._logged("User Disabled"))

	def test_holder_still_at_the_identity_provider_stays(self):
		self._bind()
		self._run_with_directory(ACCOUNT_ACTIVE)
		self.assertEqual(frappe.db.get_value("User", USER, "enabled"), 1)

	def test_provider_down_alerts_and_disables_nobody(self):
		self._bind()
		self._run_with_directory(error=DirectoryError("The identity provider answered 503"))
		self.assertEqual(frappe.db.get_value("User", USER, "enabled"), 1)
		self.assertIn("Could not be checked", self._alerts())

	def test_missing_credential_for_a_bound_holder_alerts(self):
		self._bind()
		with patch.dict(frappe.conf, {"sso_issuer": "https://idp.example.org/realms/t"}):
			frappe.conf.pop("sso_directory_client_id", None)
			with patch.object(
				api_keys.DirectoryClient, "__init__", side_effect=api_keys.SSONotConfiguredError("x")
			):
				api_keys.verify_active_api_key_users()
		rows = frappe.get_all("SSO Identity Assignment Log", {"event_type": "API Key Alert"}, pluck="details")
		self.assertTrue(any("could not be checked" in row for row in rows))
