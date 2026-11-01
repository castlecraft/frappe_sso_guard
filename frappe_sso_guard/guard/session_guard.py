import frappe


def enforce_session_guard(login_manager):
	"""Minimal session guard:

	- Guest: Always allowed.
	- CLI (bench browse): frappe.local.http_request is None -> Allowed.
	- Authorized OIDC Callback: frappe.flags.oidc_session_authorized -> Allowed.
	- When force_sso == 1: Blocks direct password/key web sessions.
	"""
	user = login_manager.user

	if user == "Guest":
		return

	# CLI bypass (bench browse)
	if not getattr(frappe.local, "http_request", None):
		return

	# Authorized by our OIDC callback
	if getattr(frappe.flags, "oidc_session_authorized", False):
		return

	conf = frappe.conf or {}
	if int(conf.get("force_sso", 1)) == 1:
		frappe.throw(
			"Single Sign-On is strictly enforced on this site. Please sign in through the identity provider.",
			exc=frappe.PermissionError,
		)
