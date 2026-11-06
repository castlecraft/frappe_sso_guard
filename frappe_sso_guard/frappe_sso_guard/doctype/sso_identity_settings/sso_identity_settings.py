# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document

from frappe_sso_guard.services.idp import get_session_max_hours_limit
from frappe_sso_guard.tasks.reconciliation import enqueue_reconciliation


class SSOIdentitySettings(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		admin_notification_emails: DF.SmallText | None
		enable_reconciliation: DF.Check
		enable_single_logout: DF.Check
		enable_team_membership: DF.Check
		groups_claim: DF.Data | None
		idp_type: DF.Literal["Keycloak", "Entra ID", "Generic OIDC"]
		inactivity_months: DF.Int
		last_reconciliation: DF.Datetime | None
		reconciliation_frequency: DF.Literal["By Hand", "Every 15 Minutes", "Hourly", "Daily"]
		reconciliation_max_disable_percent: DF.Int
		session_max_hours: DF.Int
		social_login_key: DF.Link | None
	# end: auto-generated types

	def validate(self):
		self._validate_session_max_hours()
		self._validate_max_disable_percent()

	@frappe.whitelist()
	def run_reconciliation(self):
		frappe.only_for("System Manager")
		if not self.enable_reconciliation:
			frappe.throw(_("Reconciliation is not enabled on this site."))

		enqueue_reconciliation()
		frappe.msgprint(_("Reconciliation started. Its result will be in the SSO Identity Assignment Log."))

	def _validate_max_disable_percent(self):
		# Empty on a site saved before this setting, and then the job uses its default.
		percent = self.reconciliation_max_disable_percent
		if percent and not 1 <= percent <= 100:
			frappe.throw(_("The share of users a reconciliation may disable must be between 1 and 100."))

	def _validate_session_max_hours(self):
		# Read as given: Frappe casts the field after validate, turning empty into 0 and 1.5 into 1.
		try:
			hours = float(self.session_max_hours)
		except TypeError, ValueError:
			hours = None

		if hours is None or hours < 1 or not hours.is_integer():
			frappe.throw(_("Session Max Lifetime (Hours) must be a whole number of at least 1."))

		limit = get_session_max_hours_limit()
		if hours > limit:
			frappe.throw(_("Session Max Lifetime (Hours) cannot exceed {0} on this site.").format(limit))
