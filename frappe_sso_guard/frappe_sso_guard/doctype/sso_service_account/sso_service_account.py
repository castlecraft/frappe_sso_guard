# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document

from frappe_sso_guard.guard.service_accounts import eligible_user


class SSOServiceAccount(Document):
	# begin: auto-generated types
	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		client_id: DF.Data
		enabled: DF.Check
		issuer: DF.SmallText | None
		subject: DF.Data
		user: DF.Link
	# end: auto-generated types

	def validate(self):
		if self.is_new():
			self.issuer = frappe.conf.get("sso_issuer")
		else:
			self.issuer = self.get_doc_before_save().issuer
		if not self.issuer or (self.enabled and self.issuer != frappe.conf.get("sso_issuer")):
			frappe.throw(_("Register the service account against the site's configured Keycloak issuer."))
		if self.enabled and not eligible_user(self.user):
			frappe.throw(_("Select an enabled, non-administrative integration user."))
