# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import contextlib
import io
import json
from datetime import datetime
from unittest.mock import patch

import frappe
from frappe.tests import UnitTestCase

from frappe_sso_guard.services import audit


class TestLogAuditEvent(UnitTestCase):
	def setUp(self):
		for name in ("logger", "get_doc", "log_error"):
			method_patch = patch.object(frappe, name)
			setattr(self, name, method_patch.start())
			self.addCleanup(method_patch.stop)

		# The real one reads the time zone through frappe.get_doc, which would cache the mock above.
		time_patch = patch.object(audit, "now_datetime", return_value=datetime(2026, 1, 15, 9, 30))
		time_patch.start()
		self.addCleanup(time_patch.stop)

	def _logged_event(self, logger_method):
		return json.loads(logger_method.call_args.args[0])

	def test_event_is_logged_and_persisted(self):
		audit.log_audit_event("Sign In", "Success", user="sso.user@example.com", ip_address="192.0.2.1")

		event = self._logged_event(self.logger.return_value.info)
		self.assertEqual(event["event_type"], "Sign In")
		self.assertEqual(event["ip_address"], "192.0.2.1")

		record = self.get_doc.call_args.args[0]
		self.assertEqual(record["doctype"], "SSO Identity Assignment Log")
		self.assertEqual(record["user"], "sso.user@example.com")
		self.get_doc.return_value.insert.assert_called_once_with(ignore_permissions=True)

	def test_failed_events_are_logged_as_warnings(self):
		logger = self.logger.return_value
		for status in ("Refused", "Error"):
			with self.subTest(status=status):
				audit.log_audit_event("Sign In", status)
				self.assertEqual(self._logged_event(logger.warning)["status"], status)
		logger.info.assert_not_called()

	def test_unauthenticated_events_are_not_persisted(self):
		audit.log_audit_event("Sign In", "Refused", persist=False)

		self.logger.return_value.warning.assert_called_once()
		self.get_doc.assert_not_called()

	def test_request_ip_is_used_when_none_is_passed(self):
		self.addCleanup(setattr, frappe.local, "request_ip", frappe.local.request_ip)
		frappe.local.request_ip = "192.0.2.2"

		audit.log_audit_event("Sign In", "Success")

		self.assertEqual(self.get_doc.call_args.args[0]["ip_address"], "192.0.2.2")

	def test_logger_failure_falls_back_to_stdout(self):
		self.logger.side_effect = RuntimeError("logger unavailable")

		with contextlib.redirect_stdout(io.StringIO()) as stdout:
			audit.log_audit_event("Sign In", "Success")

		self.assertIn('"event_type": "Sign In"', stdout.getvalue())
		self.get_doc.assert_called_once()

	def test_database_failure_does_not_fail_the_sign_in(self):
		self.get_doc.return_value.insert.side_effect = RuntimeError("database unavailable")

		audit.log_audit_event("Sign In", "Success")

		self.log_error.assert_called_once()


class TestNotifyAdministrators(UnitTestCase):
	def setUp(self):
		for name in ("sendmail", "log_error"):
			method_patch = patch.object(frappe, name)
			setattr(self, name, method_patch.start())
			self.addCleanup(method_patch.stop)

	def _recipients(self, value):
		return patch.object(frappe.db, "get_single_value", return_value=value)

	def test_mail_is_sent_with_the_message_escaped(self):
		with self._recipients("first@example.com, second@example.com,"):
			audit.notify_administrators("Subject", "<script>claim</script>")

		mail = self.sendmail.call_args.kwargs
		self.assertEqual(mail["recipients"], ["first@example.com", "second@example.com"])
		self.assertNotIn("<script>", mail["message"])

	def test_no_mail_without_recipients(self):
		for value in (None, "", " , "):
			with self.subTest(value=value), self._recipients(value):
				audit.notify_administrators("Subject", "Message")
		self.sendmail.assert_not_called()

	def test_mail_failure_is_logged_and_not_raised(self):
		self.sendmail.side_effect = RuntimeError("mail unavailable")

		with self._recipients("first@example.com"):
			audit.notify_administrators("Subject", "Message")

		self.log_error.assert_called_once()
