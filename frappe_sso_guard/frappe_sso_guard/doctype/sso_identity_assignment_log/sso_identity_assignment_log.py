# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document


class SSOIdentityAssignmentLog(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		details: DF.Code | None
		event_type: DF.Literal[
			"Login Success",
			"Session Refused",
			"Admin CLI Bypass",
			"User Bound",
			"Email Changed",
			"API Key Alert",
			"User Created",
			"Break-Glass Login",
			"Inactive Users Report Sent",
			"User Disabled",
			"Reconciliation Run",
			"Reconciliation Aborted",
			"API Key Created",
			"Site Settings Aligned",
		]
		idp_identifier: DF.Data | None
		ip_address: DF.Data | None
		status: DF.Literal["Success", "Warning", "Refused", "Error"]
		timestamp: DF.Datetime
		user: DF.Link | None
	# end: auto-generated types

	def validate(self):
		# Audit logs are append-only and kept for 7 years (NFR Security and Access Control). The roles
		# cannot edit or delete an entry; this stops Administrator, who ignores roles, as well.
		if not self.is_new():
			frappe.throw(_("An audit log entry cannot be changed."))

	def on_trash(self):
		frappe.throw(_("An audit log entry cannot be deleted."))
