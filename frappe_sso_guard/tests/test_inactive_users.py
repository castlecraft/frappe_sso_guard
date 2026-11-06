# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import add_to_date, now_datetime

from frappe_sso_guard.tasks.inactive_users import send_monthly_inactive_users_report


class TestInactiveUsersReport(IntegrationTestCase):
	def setUp(self):
		self.addCleanup(frappe.db.rollback)
		frappe.db.set_single_value("SSO Identity Settings", "admin_notification_emails", "admin@example.org")
		frappe.db.set_single_value("SSO Identity Settings", "inactivity_months", 6)
		sendmail = patch.object(frappe, "sendmail")
		self.sendmail = sendmail.start()
		self.addCleanup(sendmail.stop)

	def _user(self, email, last_login=None, enabled=1):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "<b>Synthetic</b>",
				"send_welcome_email": 0,
				"enabled": enabled,
				"roles": [{"role": "System Manager"}],
			}
		).insert(ignore_permissions=True)
		frappe.db.set_value("User", email, "last_login", last_login)
		return email

	def _report(self):
		send_monthly_inactive_users_report()
		return self.sendmail.call_args.kwargs["message"]

	def test_names_those_inactive_or_never_signed_in_and_no_one_else(self):
		inactive = self._user("sso.inactive@example.org", add_to_date(now_datetime(), months=-7))
		never = self._user("sso.never@example.org")
		recent = self._user("sso.recent@example.org", add_to_date(now_datetime(), months=-1))
		disabled = self._user("sso.gone@example.org", add_to_date(now_datetime(), months=-7), enabled=0)

		message = self._report()

		self.assertIn(inactive, message)
		self.assertIn(never, message)
		self.assertNotIn(recent, message)
		self.assertNotIn(disabled, message)
		self.assertNotIn("Administrator", message)

	def test_changes_nothing_and_logs_the_report(self):
		user = self._user("sso.kept.enabled@example.org", add_to_date(now_datetime(), months=-7))
		self._report()
		self.assertEqual(frappe.db.get_value("User", user, "enabled"), 1)
		self.assertTrue(
			frappe.db.exists("SSO Identity Assignment Log", {"event_type": "Inactive Users Report Sent"})
		)

	def test_without_recipients_sends_nothing(self):
		frappe.db.set_single_value("SSO Identity Settings", "admin_notification_emails", "")
		send_monthly_inactive_users_report()
		self.sendmail.assert_not_called()
