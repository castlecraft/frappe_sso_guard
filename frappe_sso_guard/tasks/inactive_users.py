from datetime import timedelta

import frappe
from frappe.utils import now_datetime

from frappe_sso_guard.services.audit import log_audit_event
from frappe_sso_guard.services.idp import get_sso_config


def send_monthly_inactive_users_report():
	"""Finds enabled users who have not logged in for the configured inactivity period

	(default: 6 months) and emails the summary to configured administrators.
	"""
	config = get_sso_config()
	inactivity_months = frappe.db.get_single_value("SSO Identity Settings", "inactivity_months") or 6
	recipient_emails = config.get("admin_notification_emails")

	if not recipient_emails:
		return

	cutoff_date = now_datetime() - timedelta(days=inactivity_months * 30)

	# Query enabled users who have not logged in since cutoff
	inactive_users = frappe.db.sql(
		"""
		SELECT name, email, full_name, last_login
		FROM `tabUser`
		WHERE enabled = 1
		  AND user_type = 'System User'
		  AND name NOT IN ('Administrator', 'Guest')
		  AND (last_login IS NULL OR last_login < %s)
		ORDER BY last_login ASC
		""",
		(cutoff_date,),
		as_dict=True,
	)

	if not inactive_users:
		return

	# Compose email report
	recipients = [e.strip() for e in recipient_emails.split(",") if e.strip()]
	subject = (
		f"[SSO Inactive Users Report] {len(inactive_users)} Users Inactive for {inactivity_months}+ Months"
	)

	rows = "".join(
		f"<tr><td>{u.name}</td><td>{u.email}</td><td>{u.last_login or 'Never'}</td></tr>"
		for u in inactive_users
	)
	message = f"""
	<h3>Inactive Users Report</h3>
	<p>The following {len(inactive_users)} enabled users have not logged in for over {inactivity_months} months:</p>
	<table border="1" cellpadding="5" cellspacing="0">
		<thead>
			<tr><th>Username</th><th>Email</th><th>Last Login</th></tr>
		</thead>
		<tbody>
			{rows}
		</tbody>
	</table>
	"""

	frappe.sendmail(
		recipients=recipients,
		subject=subject,
		message=message,
		now=True,
	)

	log_audit_event(
		event_type="Inactive Users Report Sent",
		status="Success",
		details={"inactive_count": len(inactive_users), "recipients": recipients},
	)
