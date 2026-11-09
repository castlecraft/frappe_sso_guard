# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
from frappe import _

from frappe_sso_guard.guard.session_guard import is_break_glass_user, is_sso_forced, is_web_request


def before_validate_user(doc, method=None):
	"""Runs before User.validate, which moves new_password out of the document."""
	if not is_sso_forced():
		return

	# The email's link only leads to setting a password, which is refused below.
	doc.send_welcome_email = 0

	# A bench command is left alone, as the session guard leaves it: that is how an operator sets
	# the break-glass account's first password.
	if doc.get("new_password") and is_web_request() and not is_break_glass_user(doc.name):
		frappe.throw(
			_("Passwords are managed by the identity provider on this site."), exc=frappe.PermissionError
		)


def validate_reset_password(doc, method=None):
	"""Frappe calls this for a reset request and before it keeps a new password, by key or old password."""
	if not is_sso_forced() or is_break_glass_user(doc.name):
		return

	# reset_password answers alike whatever happens, to hide which accounts exist, and only this
	# exception passes without an Error Log row per anonymous request. update_password rolls back on it.
	frappe.throw(
		_("Passwords are managed by the identity provider on this site."), exc=frappe.DoesNotExistError
	)


def before_insert_user_invitation(doc, method=None):
	if is_sso_forced():
		frappe.throw(
			_("Invitations are not used on this site: people sign in through the identity provider."),
			exc=frappe.PermissionError,
		)
