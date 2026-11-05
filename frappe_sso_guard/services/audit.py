# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import json
from typing import Any

import frappe
from frappe.utils import now_datetime
from frappe.utils.data import escape_html

LOGGER_NAME = "frappe_sso_guard"


def log_audit_event(
	event_type: str,
	status: str,
	user: str | None = None,
	idp_identifier: str | None = None,
	details: dict[str, Any] | None = None,
	ip_address: str | None = None,
	persist: bool = True,
) -> None:
	"""Logs an identity / SSO security event dual-written to:

	1. SSO Identity Assignment Log DocType (in-Frappe audit trail), unless persist is False
	2. stdout stream via frappe.logger for SOC log forwarding.

	Requests nobody has authenticated pass persist=False, so a forged callback cannot grow the table.
	"""
	if not ip_address:
		try:
			ip_address = frappe.local.request_ip if hasattr(frappe.local, "request_ip") else None
		except Exception:
			ip_address = None

	details_dict = details or {}
	details_json = json.dumps(details_dict, default=str)

	# 1. Write structured log to stdout for SOC container capture
	structured_log = {
		"timestamp": now_datetime().isoformat(),
		"event": "sso_audit",
		"event_type": event_type,
		"status": status,
		"user": user,
		"idp_identifier": idp_identifier,
		"ip_address": ip_address,
		"details": details_dict,
	}
	try:
		logger = frappe.logger(LOGGER_NAME, stream_only=True)
		log_line = json.dumps(structured_log, default=str)
		if status in ("Refused", "Error"):
			logger.warning(log_line)
		else:
			logger.info(log_line)
	except Exception:
		# Fallback to standard python print to stdout if frappe.logger unavailable
		print(f"[{LOGGER_NAME}] {json.dumps(structured_log, default=str)}", flush=True)

	if not persist:
		return

	# 2. Persist to Frappe SSO Identity Assignment Log DocType
	try:
		doc = frappe.get_doc(
			{
				"doctype": "SSO Identity Assignment Log",
				"timestamp": now_datetime(),
				"event_type": event_type,
				"status": status,
				"user": user,
				"idp_identifier": idp_identifier,
				"ip_address": ip_address,
				"details": details_json,
			}
		)
		# Written during sign-in as Guest and from background jobs: nobody holds a role to write it.
		doc.flags.ignore_permissions = True
		doc.insert(ignore_permissions=True)
	except Exception as e:
		try:
			frappe.log_error(title="SSO Audit Log DB Write Failure", message=str(e))
		except Exception:
			pass


def notify_administrators(subject: str, message: str) -> None:
	"""Emails the addresses in SSO Identity Settings. A mail failure must not change a sign-in's result."""
	recipients = frappe.db.get_single_value("SSO Identity Settings", "admin_notification_emails")
	recipients = [email.strip() for email in (recipients or "").split(",") if email.strip()]
	if not recipients:
		return

	try:
		# The message can carry claims from the token, and this mail is rendered as HTML.
		frappe.sendmail(recipients=recipients, subject=subject, message=escape_html(message))
	except Exception:
		frappe.log_error(title="SSO administrator notification failed")
