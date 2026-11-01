import unittest
from unittest.mock import MagicMock, patch

import frappe

from frappe_sso_guard.guard.session_guard import enforce_session_guard


class TestSessionGuard(unittest.TestCase):
	def setUp(self):
		frappe.flags.oidc_session_authorized = False

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
