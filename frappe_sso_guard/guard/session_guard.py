# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
from frappe import _

from frappe_sso_guard.services.audit import log_audit_event, notify_administrators
from frappe_sso_guard.services.idp import get_provider_key

ADMIN_ROLES = ("Administrator", "System Manager", "UCM Administrator", "UCM Data Manager")


def is_sso_forced() -> bool:
	conf = frappe.conf or {}
	return int(conf.get("force_sso", 1)) == 1


def get_break_glass_user() -> str | None:
	# In the site config: naming an account lets it sign in around the identity provider, so doing it
	# takes shell access, which a System Manager does not have.
	return (frappe.conf or {}).get("sso_break_glass_user")


def is_break_glass_user(user: str | None) -> bool:
	return bool(user) and user == get_break_glass_user()


def holds_admin_role(user: str) -> bool:
	return bool(set(frappe.get_roles(user)) & set(ADMIN_ROLES))


def is_bound_to_identity_provider(user: str) -> bool:
	provider = get_provider_key()
	return bool(
		provider
		and frappe.db.exists(
			"User Social Login", {"parent": user, "parenttype": "User", "provider": provider}
		)
	)


def is_web_request() -> bool:
	# A login runs inside HTTPRequest(), which sets request_ip first and http_request only once it
	# returns, so http_request alone misses it. bench browse has a request object but neither of these.
	return bool(getattr(frappe.local, "http_request", None) or getattr(frappe.local, "request_ip", None))


def enforce_session_guard(login_manager):
	"""Minimal session guard:

	- Guest: Always allowed.
	- CLI (bench browse): no web request -> Allowed, logged and notified.
	- Authorized OIDC Callback: frappe.flags.oidc_session_authorized -> Allowed.
	- When force_sso == 1: Blocks every other web session but the break-glass account's, whichever
	  path opened it: password, email link, reset key or invitation.
	- When force_sso == 0: The same for a User bound to the identity provider or holding an
	  administrative role, so that a site that also serves people the provider does not know leaves
	  its staff and administrators no way around it.
	"""
	user = login_manager.user

	if user == "Guest":
		return

	# CLI bypass (bench browse)
	if not is_web_request():
		log_audit_event(
			event_type="Admin CLI Bypass",
			status="Warning",
			user=user,
			details={"reason": "A session opened from the server"},
		)
		notify_administrators(
			_("Single sign-on: {0} signed in from the server").format(user),
			_("{0} opened a session from the server, without the identity provider.").format(user),
		)
		return

	# Authorized by our OIDC callback
	if getattr(frappe.flags, "oidc_session_authorized", False):
		return

	if not is_sso_forced() and not is_bound_to_identity_provider(user) and not holds_admin_role(user):
		return

	if is_break_glass_user(user):
		log_audit_event(event_type="Break-Glass Login", status="Warning", user=user)
		notify_administrators(
			_("Single sign-on: break-glass sign-in by {0}").format(user),
			_("{0} signed in without the identity provider.").format(user),
		)
		return

	log_audit_event(
		event_type="Session Refused",
		status="Refused",
		user=user,
		details={"reason": "A web session the identity provider did not open"},
	)
	notify_administrators(
		_("Single sign-on refused for {0}").format(user),
		_("{0} tried to open a session without the identity provider.").format(user),
	)
	if not frappe.in_test:
		# nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit -- reviewed: the refusal below rolls the request back, which would lose the record of it.
		frappe.db.commit()

	frappe.throw(
		_("Single Sign-On is strictly enforced on this site. Please sign in through the identity provider."),
		exc=frappe.PermissionError,
	)
