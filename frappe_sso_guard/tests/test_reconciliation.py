# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from unittest.mock import MagicMock, patch

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import add_to_date, now_datetime

from frappe_sso_guard.services import directory
from frappe_sso_guard.services.directory import (
	ACCOUNT_ACTIVE,
	ACCOUNT_DISABLED,
	ACCOUNT_REMOVED,
	DirectoryError,
)
from frappe_sso_guard.tasks import reconciliation

PROVIDER_KEY = "test_sso_reconcile"
ISSUER = "https://idp.example.org/realms/test"


class TestReconciliation(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
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
		settings = frappe.get_single("SSO Identity Settings")
		settings.social_login_key = PROVIDER_KEY
		settings.idp_type = "Keycloak"
		settings.admin_notification_emails = ""
		settings.enable_reconciliation = 1
		settings.reconciliation_frequency = "By Hand"
		settings.reconciliation_max_disable_percent = 10
		settings.last_reconciliation = None
		settings.save()

		self.statuses = {}
		client = MagicMock()
		client.get_account_status.side_effect = self._status
		for patcher in (
			patch.dict(
				frappe.conf,
				{
					"sso_issuer": ISSUER,
					"sso_directory_client_id": "reader",
					"sso_directory_client_secret": "synthetic",
				},
			),
			patch.object(reconciliation, "DirectoryClient", return_value=client),
			# Ending a session commits, and this test must roll back.
			patch.object(frappe.db, "commit"),
		):
			patcher.start()
			self.addCleanup(patcher.stop)
		self.addCleanup(frappe.db.rollback)

	def _status(self, identifier):
		status = self.statuses[identifier]
		if isinstance(status, Exception):
			raise status
		return status

	def _bound_user(self, name, status=ACCOUNT_ACTIVE):
		# Not the realm file's addresses: a developer's own sign-ins through setup_keycloak created those.
		email = f"test.{name}@example.org"
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "Synthetic",
				"send_welcome_email": 0,
				"social_logins": [{"provider": PROVIDER_KEY, "userid": name}],
			}
		).insert(ignore_permissions=True)
		self.statuses[name] = status
		return email

	def _enabled(self, user):
		return frappe.db.get_value("User", user, "enabled")

	def _logged(self, event_type, **filters):
		return frappe.db.exists("SSO Identity Assignment Log", {"event_type": event_type, **filters})

	def test_disables_those_disabled_or_removed_and_logs_each(self):
		active = self._bound_user("sso.active")
		disabled = self._bound_user("sso.disabled", ACCOUNT_DISABLED)
		removed = self._bound_user("sso.removed", ACCOUNT_REMOVED)

		summary = reconciliation.reconcile_users()

		self.assertEqual(summary["disabled"], 2)
		self.assertEqual(self._enabled(active), 1)
		self.assertEqual(self._enabled(disabled), 0)
		self.assertEqual(self._enabled(removed), 0)
		self.assertTrue(self._logged("User Disabled", user=disabled, idp_identifier="sso.disabled"))
		self.assertTrue(self._logged("Reconciliation Run"))

	def test_user_is_disabled_not_deleted(self):
		user = self._bound_user("sso.kept", ACCOUNT_REMOVED)
		reconciliation.reconcile_users()
		self.assertTrue(frappe.db.exists("User", user))

	def test_sessions_of_a_disabled_user_are_ended_inside_a_job(self):
		user = self._bound_user("sso.session", ACCOUNT_DISABLED)
		with patch.object(reconciliation, "clear_sessions") as clear_sessions:
			reconciliation.reconcile_users()
		clear_sessions.assert_called_once_with(user=user, force=True)

	def test_provider_failing_halfway_disables_nobody(self):
		first = self._bound_user("sso.first", ACCOUNT_DISABLED)
		second = self._bound_user("sso.second", DirectoryError("The identity provider answered 503"))

		summary = reconciliation.reconcile_users()

		self.assertEqual(summary["disabled"], 0)
		self.assertEqual(self._enabled(first), 1)
		self.assertEqual(self._enabled(second), 1)
		self.assertTrue(self._logged("Reconciliation Aborted"))

	def test_too_many_leavers_disables_nobody_and_notifies(self):
		# What a wrong realm looks like: the provider answers that every account is gone.
		users = [self._bound_user(f"sso.gone{n}", ACCOUNT_REMOVED) for n in range(6)]
		frappe.db.set_single_value("SSO Identity Settings", "admin_notification_emails", "admin@example.org")

		with patch.object(frappe, "sendmail") as sendmail:
			summary = reconciliation.reconcile_users()

		self.assertEqual(summary["disabled"], 0)
		self.assertTrue(all(self._enabled(user) == 1 for user in users))
		self.assertTrue(self._logged("Reconciliation Aborted"))
		sendmail.assert_called_once()

	def test_a_few_leavers_on_a_small_site_are_allowed(self):
		users = [self._bound_user(f"sso.few{n}", ACCOUNT_REMOVED) for n in range(5)]
		reconciliation.reconcile_users()
		self.assertTrue(all(self._enabled(user) == 0 for user in users))

	def test_break_glass_account_is_left_alone(self):
		user = self._bound_user("sso.glass", ACCOUNT_REMOVED)

		with patch.dict(frappe.conf, {"sso_break_glass_user": user}):
			reconciliation.reconcile_users()

		self.assertEqual(self._enabled(user), 1)

	def test_user_bound_to_another_provider_is_left_alone(self):
		user = self._bound_user("sso.other")
		frappe.db.set_value(
			"User Social Login", {"parent": user, "userid": "sso.other"}, "provider", "another_provider"
		)
		reconciliation.reconcile_users()
		self.assertEqual(self._enabled(user), 1)

	def test_user_frappe_refuses_to_disable_is_counted_not_fatal(self):
		refused = self._bound_user("sso.refused", ACCOUNT_DISABLED)
		next_user = self._bound_user("sso.next", ACCOUNT_DISABLED)
		save = frappe.model.document.Document.save

		def refuse_one(doc, *args, **kwargs):
			if doc.doctype == "User" and doc.name == refused:
				frappe.throw("Refused")
			return save(doc, *args, **kwargs)

		with patch.object(frappe.model.document.Document, "save", refuse_one):
			summary = reconciliation.reconcile_users()

		self.assertEqual(summary["failed"], 1)
		self.assertEqual(summary["disabled"], 1)
		self.assertEqual(self._enabled(refused), 1)
		self.assertEqual(self._enabled(next_user), 0)

	def test_schedule_runs_only_when_enabled_and_due(self):
		cases = [
			(1, "By Hand", None, False),
			(0, "Hourly", None, False),
			(1, "Hourly", None, True),
			(1, "Hourly", add_to_date(now_datetime(), minutes=-61), True),
			(1, "Hourly", add_to_date(now_datetime(), minutes=-10), False),
			(1, "Every 15 Minutes", add_to_date(now_datetime(), minutes=-14), True),
			(1, "Daily", add_to_date(now_datetime(), hours=-3), False),
		]
		for enabled, frequency, last_run, expected in cases:
			with self.subTest(enabled=enabled, frequency=frequency, last_run=last_run):
				frappe.db.set_single_value("SSO Identity Settings", "enable_reconciliation", enabled)
				frappe.db.set_single_value("SSO Identity Settings", "reconciliation_frequency", frequency)
				frappe.db.set_single_value("SSO Identity Settings", "last_reconciliation", last_run)
				with patch.object(reconciliation, "enqueue_reconciliation") as enqueue:
					reconciliation.run_scheduled_reconciliation()
				self.assertEqual(enqueue.called, expected)

	def test_settings_button_refuses_when_not_enabled(self):
		frappe.db.set_single_value("SSO Identity Settings", "enable_reconciliation", 0)
		with self.assertRaises(frappe.ValidationError):
			frappe.get_single("SSO Identity Settings").run_reconciliation()

	def test_settings_button_needs_a_system_manager(self):
		frappe.set_user("Guest")
		self.addCleanup(frappe.set_user, "Administrator")
		with self.assertRaises(frappe.PermissionError):
			frappe.get_single("SSO Identity Settings").run_reconciliation()


class TestDirectoryClient(IntegrationTestCase):
	"""The requests as the real provider's API takes them, on a real site's configuration."""

	def test_keycloak_and_graph_answers_reach_a_status(self):
		cases = [
			("Keycloak", ISSUER, {"enabled": False}, ACCOUNT_DISABLED),
			("Entra ID", "https://login.example.org/t/v2.0", {"accountEnabled": True}, ACCOUNT_ACTIVE),
		]
		for idp_type, issuer, body, expected in cases:
			with self.subTest(idp_type=idp_type):
				with (
					patch.dict(
						frappe.conf,
						{"sso_directory_client_id": "reader", "sso_directory_client_secret": "synthetic"},
					),
					patch.object(
						directory, "get_openid_configuration", return_value={"token_endpoint": "https://t"}
					),
					patch.object(
						directory.requests,
						"post",
						return_value=MagicMock(status_code=200, json=lambda: {"access_token": "t"}),
					),
					patch.object(
						directory.requests, "get", return_value=MagicMock(status_code=200, json=lambda: body)
					),
				):
					client = directory.DirectoryClient(idp_type, issuer)
					self.assertEqual(client.get_account_status("id:tenant"), expected)
