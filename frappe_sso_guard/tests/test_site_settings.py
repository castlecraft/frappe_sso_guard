# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import json
from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

from frappe_sso_guard import install
from frappe_sso_guard.guard import password_guard, site_settings

EVENT = "Site Settings Aligned"
INVITED = "sso.invited@example.org"


def _forced(forced):
	return patch.object(site_settings, "is_sso_forced", return_value=forced)


def _web_request(is_web):
	return patch.object(site_settings, "is_web_request", return_value=is_web)


class TestSiteSettings(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		self.addCleanup(self._forget_cached_settings)
		self.addCleanup(frappe.db.rollback)
		commit = patch.object(frappe.db, "commit")
		commit.start()
		self.addCleanup(commit.stop)
		sendmail = patch.object(frappe, "sendmail")
		self.sendmail = sendmail.start()
		self.addCleanup(sendmail.stop)
		# As a site that had force_sso off until now.
		frappe.db.set_single_value("System Settings", "login_with_email_link", 1)
		frappe.db.set_single_value("Website Settings", "disable_signup", 0)

	def _forget_cached_settings(self):
		# A test can cache a value the rollback then removes.
		frappe.clear_document_cache("System Settings", "System Settings")
		frappe.clear_document_cache("Website Settings", "Website Settings")

	def _assert_aligned(self, aligned):
		self.assertEqual(frappe.db.get_single_value("System Settings", "login_with_email_link"), not aligned)
		self.assertEqual(frappe.db.get_single_value("Website Settings", "disable_signup"), aligned)

	def _invitation(self, email=INVITED):
		# The password guard refuses new invitations on a forced site, and these came before.
		with patch.object(password_guard, "is_sso_forced", return_value=False):
			return frappe.get_doc(
				{
					"doctype": "User Invitation",
					"email": email,
					"app_name": "frappe",
					"redirect_to_path": "/desk",
					"roles": [{"role": "System Manager"}],
				}
			).insert()

	def _log_count(self):
		return frappe.db.count("SSO Identity Assignment Log", {"event_type": EVENT})

	# Install and migrate

	def test_forced_site_turns_the_email_link_off_and_sign_ups_off(self):
		with _forced(True):
			site_settings.align_site_with_force_sso()
		self._assert_aligned(True)

	def test_cached_settings_follow(self):
		self.assertFalse(frappe.client_cache.get_doc("Website Settings").disable_signup)
		self.assertTrue(frappe.client_cache.get_doc("System Settings").login_with_email_link)
		with _forced(True):
			site_settings.align_site_with_force_sso()
		self.assertTrue(frappe.client_cache.get_doc("Website Settings").disable_signup)
		self.assertFalse(frappe.client_cache.get_doc("System Settings").login_with_email_link)

	def test_site_not_forced_is_left_as_it_is(self):
		invitation = self._invitation()
		with _forced(False):
			site_settings.align_site_with_force_sso()
		self._assert_aligned(False)
		self.assertEqual(invitation.reload().status, "Pending")

	def test_install_and_migrate_both_align_the_site(self):
		for hook in (install.after_install, install.after_migrate):
			with (
				self.subTest(hook=hook.__name__),
				patch.object(install, "align_site_with_force_sso") as align,
			):
				hook()
				align.assert_called_once_with()

	def test_change_is_logged_with_what_changed(self):
		self._invitation()
		before = self._log_count()
		with _forced(True):
			site_settings.align_site_with_force_sso()
		self.assertEqual(self._log_count(), before + 1)
		details = frappe.get_all(
			"SSO Identity Assignment Log",
			filters={"event_type": EVENT},
			pluck="details",
			order_by="creation desc",
			limit=1,
		)[0]
		details = json.loads(details)
		self.assertEqual(details["settings"], ["login_with_email_link", "disable_signup"])
		self.assertGreaterEqual(details["invitations_expired"], 1)

	def test_an_aligned_site_logs_nothing_at_the_next_migrate(self):
		with _forced(True):
			site_settings.align_site_with_force_sso()
			before = self._log_count()
			site_settings.align_site_with_force_sso()
		self.assertEqual(self._log_count(), before)

	# Invitations

	def test_pending_invitation_expires_and_its_link_stops_working(self):
		invitation = self._invitation()
		with _forced(True):
			site_settings.align_site_with_force_sso()
		self.assertEqual(invitation.reload().status, "Expired")
		with self.assertRaises(frappe.ValidationError):
			invitation.accept(ignore_permissions=True)

	def test_expiring_an_invitation_sends_no_email(self):
		self._invitation()
		self.sendmail.reset_mock()
		with _forced(True):
			site_settings.align_site_with_force_sso()
		self.sendmail.assert_not_called()

	def test_accepted_invitation_is_left_as_it_is(self):
		invitation = self._invitation()
		frappe.db.set_value("User Invitation", invitation.name, "status", "Accepted")
		with _forced(True):
			site_settings.align_site_with_force_sso()
		self.assertEqual(invitation.reload().status, "Accepted")

	# Changes from the web

	def test_web_save_turning_the_email_link_on_is_refused(self):
		settings = frappe.get_single("System Settings")
		with _forced(True), _web_request(True), self.assertRaises(frappe.ValidationError):
			settings.save()

	def test_web_save_allowing_sign_ups_is_refused(self):
		settings = frappe.get_single("Website Settings")
		with _forced(True), _web_request(True), self.assertRaises(frappe.ValidationError):
			settings.save()

	def test_aligned_settings_can_be_saved(self):
		allowed = frappe._dict(login_with_email_link=0, disable_signup=1)
		with _forced(True), _web_request(True):
			site_settings.validate_system_settings(allowed)
			site_settings.validate_website_settings(allowed)

	def test_bench_command_and_site_not_forced_are_left_alone(self):
		settings = frappe._dict(login_with_email_link=1, disable_signup=0)
		for forced, is_web in ((True, False), (False, True)):
			with self.subTest(forced=forced, is_web=is_web), _forced(forced), _web_request(is_web):
				site_settings.validate_system_settings(settings)
				site_settings.validate_website_settings(settings)
