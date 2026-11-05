# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

app_name = "frappe_sso_guard"
app_title = "Frappe SSO Guard"
app_publisher = "ICRC / Castlecraft"
app_description = "Frappe SSO Guard with strict OIDC enforcement"
app_email = "support@castlecraft.in"
app_license = "mit"

export_python_type_annotations = True

# Minimal, essential hooks
on_login = "frappe_sso_guard.guard.session_guard.enforce_session_guard"
on_logout = "frappe_sso_guard.guard.login_page.remember_logout"
update_website_context = "frappe_sso_guard.guard.login_page.redirect_login_page"

doc_events = {
	"User": {
		"before_validate": "frappe_sso_guard.guard.password_guard.before_validate_user",
		"validate_reset_password": "frappe_sso_guard.guard.password_guard.validate_reset_password",
	},
	"User Invitation": {
		"before_insert": "frappe_sso_guard.guard.password_guard.before_insert_user_invitation",
	},
}

# Scheduled background jobs
scheduler_events = {
	"monthly": ["frappe_sso_guard.tasks.inactive_users.send_monthly_inactive_users_report"],
	"daily": ["frappe_sso_guard.tasks.api_keys.verify_active_api_key_users"],
}
