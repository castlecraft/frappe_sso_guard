# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

from frappe_sso_guard.guard.api_key_guard import API_KEY_ALLOWED_FIELD


def after_install():
	ensure_custom_fields()


def after_migrate():
	ensure_custom_fields()


def ensure_custom_fields():
	create_custom_fields(
		{
			"User": [
				{
					"fieldname": API_KEY_ALLOWED_FIELD,
					"fieldtype": "Check",
					"label": "Allowed To Hold An API Key",
					"insert_after": "api_secret",
					# As the key itself: people can edit their own User, and must not flag themselves.
					"permlevel": 1,
					"description": "A service account or a data scientist. Needs Restrict IP and no administrative role.",
				}
			]
		},
		update=True,
	)
