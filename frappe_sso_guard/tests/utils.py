# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe


def remove_traces_of_deleted(doctype: str, names: tuple[str, ...]) -> None:
	"""A test that had to commit its records also commits what deleting them leaves behind."""
	frappe.db.delete("Deleted Document", {"deleted_doctype": doctype, "deleted_name": ("in", names)})
	subjects = tuple(f"{doctype} {name}" for name in names)
	frappe.db.delete("Comment", {"comment_type": "Deleted", "subject": ("in", subjects)})


def remove_traces_of_deleted_users(users: tuple[str, ...]) -> None:
	# Deleting a User ends its sessions, which logs that, and deletes its Notification Settings.
	frappe.db.delete("Activity Log", {"user": ("in", users)})
	remove_traces_of_deleted("User", users)
	remove_traces_of_deleted("Notification Settings", users)
