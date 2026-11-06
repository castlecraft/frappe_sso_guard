# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

from frappe_sso_guard.services.idp import get_sso_config


class IntegrationTestSSOIdentitySettings(IntegrationTestCase):
	def test_the_form_is_told_whether_the_scheduler_is_off(self):
		module = "frappe_sso_guard.frappe_sso_guard.doctype.sso_identity_settings.sso_identity_settings"
		for inactive in (True, False):
			with (
				self.subTest(inactive=inactive),
				patch(f"{module}.is_scheduler_inactive", return_value=inactive),
			):
				settings = frappe.get_single("SSO Identity Settings")
				settings.run_method("onload")
				self.assertIs(settings.get_onload("scheduler_inactive"), inactive)

	def _set_session_max_hours(self, hours):
		settings = frappe.get_single("SSO Identity Settings")
		settings.session_max_hours = hours
		settings.save()

	def test_settings_page_refuses_anything_but_a_whole_number_of_at_least_one(self):
		self._set_session_max_hours(7)
		for value in (0, -1, None, "", 1.5, "1.5", "twelve"):
			with self.subTest(value=value):
				with self.assertRaises(frappe.ValidationError):
					self._set_session_max_hours(value)
				self.assertEqual(frappe.db.get_single_value("SSO Identity Settings", "session_max_hours"), 7)

	def test_settings_page_accepts_one_hour(self):
		self._set_session_max_hours(1)
		self.assertEqual(frappe.db.get_single_value("SSO Identity Settings", "session_max_hours"), 1)

	def test_session_cannot_exceed_the_limit_in_the_site_config(self):
		with self.assertRaises(frappe.ValidationError):
			self._set_session_max_hours(13)

		with patch.dict(frappe.conf, {"sso_session_max_hours_limit": 24}):
			self._set_session_max_hours(24)
		self.assertEqual(frappe.db.get_single_value("SSO Identity Settings", "session_max_hours"), 24)

	def test_session_written_past_the_limit_is_still_held_to_it(self):
		frappe.db.set_single_value("SSO Identity Settings", "session_max_hours", 48)
		self.assertEqual(get_sso_config()["session_max_hours"], 12)

	def test_share_a_reconciliation_may_disable_must_be_a_percentage(self):
		settings = frappe.get_single("SSO Identity Settings")
		settings.reconciliation_max_disable_percent = 101
		with self.assertRaises(frappe.ValidationError):
			settings.save()
