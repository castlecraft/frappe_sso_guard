# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import unittest
from unittest.mock import MagicMock, patch

import frappe

from frappe_sso_guard.guard.session_guard import enforce_session_guard


class TestSessionGuard(unittest.TestCase):
	def setUp(self):
		frappe.flags.oidc_session_authorized = False
		# The users here do not exist, so the audit entry fails and logs that, and Error Log is
		# MyISAM: its rows outlive a rollback.
		log_error = patch.object(frappe, "log_error")
		log_error.start()
		self.addCleanup(log_error.stop)

	def tearDown(self):
		frappe.flags.oidc_session_authorized = False

	def test_guest_is_always_allowed(self):
		"""Guest is permitted through."""
		mock_lm = MagicMock(user="Guest")
		enforce_session_guard(mock_lm)

	def test_cli_bench_browse_bypass(self):
		"""CLI executions (bench browse) have http_request = None and are allowed."""
		mock_lm = MagicMock(user="Administrator")
		frappe.local.http_request = None
		try:
			with patch("frappe_sso_guard.guard.session_guard.log_audit_event") as log:
				enforce_session_guard(mock_lm)
			self.assertEqual(log.call_args.kwargs["event_type"], "Admin CLI Bypass")
		finally:
			if hasattr(frappe.local, "http_request"):
				delattr(frappe.local, "http_request")

	def test_administrator_is_refused_when_sso_is_not_forced(self):
		mock_lm = MagicMock(user="Administrator")
		frappe.local.http_request = MagicMock()
		try:
			with (
				# A site may name Administrator as its break-glass account, which would let it through.
				patch.dict(frappe.conf, {"force_sso": 0, "sso_break_glass_user": None}),
				patch(
					"frappe_sso_guard.guard.session_guard.is_bound_to_identity_provider", return_value=False
				),
				patch("frappe_sso_guard.guard.session_guard.log_audit_event"),
				self.assertRaises(frappe.PermissionError),
			):
				enforce_session_guard(mock_lm)
		finally:
			if hasattr(frappe.local, "http_request"):
				delattr(frappe.local, "http_request")

	def test_bound_user_is_refused_when_sso_is_not_forced(self):
		"""A site serving people the provider does not know still holds its staff to the provider."""
		mock_lm = MagicMock(user="bound_user@example.com")
		frappe.local.http_request = MagicMock()
		try:
			with (
				patch.dict(frappe.conf, {"force_sso": 0}),
				patch(
					"frappe_sso_guard.guard.session_guard.is_bound_to_identity_provider", return_value=True
				),
				self.assertRaises(frappe.PermissionError),
			):
				enforce_session_guard(mock_lm)
		finally:
			if hasattr(frappe.local, "http_request"):
				delattr(frappe.local, "http_request")

	def test_oidc_authorized_flag_allowed(self):
		"""Logins authorized by our callback (frappe.flags.oidc_session_authorized) are allowed."""
		mock_lm = MagicMock(user="test_sso_user@example.com")
		frappe.flags.oidc_session_authorized = True

		frappe.local.http_request = MagicMock()
		try:
			enforce_session_guard(mock_lm)
		finally:
			if hasattr(frappe.local, "http_request"):
				delattr(frappe.local, "http_request")

	@patch.dict(frappe.conf, {"force_sso": 1})
	def test_unauthorized_web_login_refused_when_force_sso(self):
		"""Any unauthorized web login is rejected when force_sso == 1."""
		mock_lm = MagicMock(user="direct_user@example.com")
		frappe.flags.oidc_session_authorized = False

		frappe.local.http_request = MagicMock()
		try:
			with self.assertRaises(frappe.PermissionError):
				enforce_session_guard(mock_lm)
		finally:
			if hasattr(frappe.local, "http_request"):
				delattr(frappe.local, "http_request")
