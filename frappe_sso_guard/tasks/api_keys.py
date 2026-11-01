import frappe

from frappe_sso_guard.services.audit import log_audit_event
from frappe_sso_guard.services.idp import get_sso_config


def verify_active_api_key_users():
	"""Daily verification task for users holding API keys:

	- Checks that API key holders maintain valid Restrict IP settings.
	- Ensures no admin roles have been assigned to API key holders.
	- Logs alerts for any violations.
	"""
	# Find all enabled users holding API keys
	key_holders = frappe.db.sql(
		"""
		SELECT name, email, restrict_ip
		FROM `tabUser`
		WHERE enabled = 1
		  AND api_key IS NOT NULL
		  AND api_key != ''
		""",
		as_dict=True,
	)

	for user in key_holders:
		# Check Restrict IP
		if not user.restrict_ip:
			log_audit_event(
				event_type="API Key Alert",
				status="Warning",
				user=user.name,
				details={"issue": "User has API key but Restrict IP is missing"},
			)

		# Check Admin roles
		roles = frappe.get_roles(user.name)
		if any(r in ["System Manager", "Administrator"] for r in roles):
			log_audit_event(
				event_type="API Key Alert",
				status="Refused",
				user=user.name,
				details={"issue": "User has API key AND administrative roles (Security Violation)"},
			)
