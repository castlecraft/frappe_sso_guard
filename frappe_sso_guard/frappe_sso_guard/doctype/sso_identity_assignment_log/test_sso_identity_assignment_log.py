# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import now_datetime

import frappe_sso_guard.hooks

LOG = "SSO Identity Assignment Log"


class IntegrationTestSSOIdentityAssignmentLog(IntegrationTestCase):
	def _insert_log(self):
		return frappe.get_doc(
			{
				"doctype": LOG,
				"timestamp": now_datetime(),
				"event_type": "Login Success",
				"status": "Success",
			}
		).insert()

	def test_an_entry_cannot_be_changed(self):
		log = self._insert_log()
		log.status = "Refused"
		with self.assertRaises(frappe.ValidationError):
			log.save()

	def test_an_entry_cannot_be_deleted(self):
		log = self._insert_log()
		with self.assertRaises(frappe.ValidationError):
			log.delete()

	def test_nothing_clears_old_entries(self):
		# Kept for 7 years, so the log must stay out of Frappe's nightly clearing.
		self.assertNotIn(LOG, getattr(frappe_sso_guard.hooks, "default_log_clearing_doctypes", {}))
		self.assertFalse(hasattr(frappe.get_doc(LOG, self._insert_log().name), "clear_old_logs"))

	def test_no_role_can_write_an_entry(self):
		for permission in frappe.get_meta(LOG).permissions:
			self.assertFalse(permission.create or permission.write or permission.delete)
