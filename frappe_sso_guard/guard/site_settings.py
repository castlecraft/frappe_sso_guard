# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.utils import cint

from frappe_sso_guard.guard.session_guard import is_sso_forced, is_web_request
from frappe_sso_guard.services.audit import log_audit_event

REQUIRED_SETTINGS = (
	("System Settings", "login_with_email_link", 0),
	("Website Settings", "disable_signup", 1),
)


def validate_system_settings(doc, method=None):
	if _is_held_to_force_sso() and doc.login_with_email_link:
		frappe.throw(
			_("Login with email link stays off on this site: people sign in through the identity provider.")
		)


def validate_website_settings(doc, method=None):
	if _is_held_to_force_sso() and not doc.disable_signup:
		frappe.throw(_("Disable Signup stays on on this site: people sign in through the identity provider."))


def align_site_with_force_sso():
	"""Runs at install and at each migrate: force_sso is in the site config, and changing that runs no code."""
	if not is_sso_forced():
		return

	settings = _apply_required_settings()
	invitations = _expire_pending_invitations()
	if settings or invitations:
		log_audit_event(
			event_type="Site Settings Aligned",
			status="Success",
			details={"settings": settings, "invitations_expired": invitations},
		)


def _is_held_to_force_sso() -> bool:
	# A bench command is left alone, as in the password guard: changing these from there takes shell access.
	return is_sso_forced() and is_web_request()


def _apply_required_settings() -> list[str]:
	changed = []
	for doctype, fieldname, value in REQUIRED_SETTINGS:
		if cint(frappe.db.get_single_value(doctype, fieldname)) != value:
			frappe.db.set_single_value(doctype, fieldname, value)
			changed.append(fieldname)
	return changed


def _expire_pending_invitations() -> int:
	pending = frappe.get_all("User Invitation", filters={"status": "Pending"}, pluck="name")
	# Not its expire(), which also emails each person: a deployment should not write to them, or
	# depend on the site having a mail account.
	for name in pending:
		frappe.db.set_value("User Invitation", name, "status", "Expired")
	return len(pending)
