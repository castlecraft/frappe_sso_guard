import frappe
from frappe.utils import get_datetime, now_datetime

from frappe_sso_guard.services.audit import log_audit_event


def enforce_session_expiry():
	"""Runs on before_request hook.

	Ensures absolute session lifetime (session_end) is strictly enforced,
	even when a session loads from the database after a Redis cache flush/restart.
	(Raffael correction #7: Frappe only checks session_end when reading from Redis).
	"""
	# Guest sessions do not have session_end
	if not frappe.session or frappe.session.user == "Guest":
		return

	session_data = getattr(frappe.session, "data", None)
	if not session_data:
		return

	session_end_str = session_data.get("session_end")
	if not session_end_str:
		return

	try:
		session_end = get_datetime(session_end_str)
		if now_datetime() >= session_end:
			user = frappe.session.user
			log_audit_event(
				event_type="Session Refused",
				status="Refused",
				user=user,
				details={"reason": "Absolute session lifetime expired", "session_end": session_end_str},
			)
			if hasattr(frappe.local, "login_manager"):
				frappe.local.login_manager.logout()
			else:
				frappe.destroy_session()
			frappe.throw("Your session has expired. Please sign in again.", exc=frappe.SessionStopped)
	except frappe.SessionStopped, frappe.ValidationError:
		raise
	except Exception:
		pass
