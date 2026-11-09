# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from datetime import timedelta

import frappe
from frappe import _
from frappe.utils import now_datetime
from frappe.utils.data import escape_html

from frappe_sso_guard.services.audit import log_audit_event
from frappe_sso_guard.services.idp import get_sso_config


def send_monthly_inactive_users_report():
	"""Emails the administrators the enabled users who have not signed in for the configured period.

	It changes nothing: the people named may simply be on leave.
	"""
	config = get_sso_config()
	inactivity_months = frappe.db.get_single_value("SSO Identity Settings", "inactivity_months") or 6
	recipients = [e.strip() for e in (config.get("admin_notification_emails") or "").split(",") if e.strip()]
	if not recipients:
		return

	cutoff_date = now_datetime() - timedelta(days=inactivity_months * 30)
	inactive_users = frappe.get_all(
		"User",
		filters={"enabled": 1, "user_type": "System User", "name": ("not in", frappe.STANDARD_USERS)},
		or_filters=[["last_login", "is", "not set"], ["last_login", "<", cutoff_date]],
		fields=["name", "last_login"],
		order_by="last_login asc",
	)
	if not inactive_users:
		return

	rows = "".join(
		f"<tr><td>{escape_html(user.name)}</td><td>{user.last_login or _('Never')}</td></tr>"
		for user in inactive_users
	)
	message = f"""
	<p>{_("These {0} enabled users have not signed in for over {1} months:").format(len(inactive_users), inactivity_months)}</p>
	<table border="1" cellpadding="5" cellspacing="0">
		<thead><tr><th>{_("User")}</th><th>{_("Last Login")}</th></tr></thead>
		<tbody>{rows}</tbody>
	</table>
	"""

	frappe.sendmail(
		recipients=recipients,
		subject=_("Single sign-on: {0} inactive users").format(len(inactive_users)),
		message=message,
		now=True,
	)

	log_audit_event(
		event_type="Inactive Users Report Sent",
		status="Success",
		details={"inactive_count": len(inactive_users), "recipients": recipients},
	)
