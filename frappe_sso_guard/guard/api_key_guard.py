# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
from frappe import _

from frappe_sso_guard.guard.session_guard import ADMIN_ROLES, is_sso_forced, is_web_request
from frappe_sso_guard.services.audit import log_audit_event

API_KEY_ALLOWED_FIELD = "sso_api_key_allowed"
NEW_KEY_FLAG = "sso_new_api_key"


def validate_user_api_key(doc, method=None):
	"""Holds each API key to a flagged User, held to the VPN, with no administrative role.

	Frappe's generate_keys lets any System Manager create a key for any User, and a key opens no
	session, so neither the session guard nor the session's end ever applies to it.
	"""
	new_key = _has_new_key(doc)
	doc.flags[NEW_KEY_FLAG] = new_key

	# A bench command is left alone, as the other guards leave it; the daily check still reports it.
	if not doc.api_key or not is_sso_forced() or not is_web_request():
		return
	# A User who already holds a key can still save their profile until these rules change for them.
	if not new_key and not _rules_changed(doc):
		return

	if not doc.get(API_KEY_ALLOWED_FIELD):
		frappe.throw(_("This user is not flagged to hold an API key."), exc=frappe.PermissionError)
	if not doc.restrict_ip:
		frappe.throw(_("A user holding an API key must have Restrict IP set."), exc=frappe.PermissionError)
	if {row.role for row in doc.get("roles")} & set(ADMIN_ROLES):
		frappe.throw(
			_("A user holding an API key cannot hold an administrative role."), exc=frappe.PermissionError
		)


def log_new_api_key(doc, method=None):
	if doc.flags.get(NEW_KEY_FLAG):
		log_audit_event(
			event_type="API Key Created",
			status="Warning",
			user=doc.name,
			details={"created_by": frappe.session.user},
		)


def _has_new_key(doc) -> bool:
	# Password fields read as asterisks until generate_keys sets a real value.
	return bool(doc.api_key and doc.api_secret and not doc.is_dummy_password(doc.api_secret))


def _rules_changed(doc) -> bool:
	if doc.is_new():
		return True
	if any(doc.has_value_changed(field) for field in ("api_key", "restrict_ip", API_KEY_ALLOWED_FIELD)):
		return True
	before = doc.get_doc_before_save()
	if not before:
		return True
	return {row.role for row in before.get("roles")} != {row.role for row in doc.get("roles")}
