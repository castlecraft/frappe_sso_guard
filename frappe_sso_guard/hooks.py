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

# Lets an app holding teams ask whether this site takes their members from the identity provider.
ucm_team_membership_from_idp = "frappe_sso_guard.services.team_membership.is_enabled"

after_install = "frappe_sso_guard.install.after_install"
after_migrate = "frappe_sso_guard.install.after_migrate"

doc_events = {
	"User": {
		"before_validate": "frappe_sso_guard.guard.password_guard.before_validate_user",
		"validate": "frappe_sso_guard.guard.api_key_guard.validate_user_api_key",
		"on_update": "frappe_sso_guard.guard.api_key_guard.log_new_api_key",
		"validate_reset_password": "frappe_sso_guard.guard.password_guard.validate_reset_password",
	},
	"User Invitation": {
		"before_insert": "frappe_sso_guard.guard.password_guard.before_insert_user_invitation",
	},
	"System Settings": {
		"validate": "frappe_sso_guard.guard.site_settings.validate_system_settings",
	},
	"Website Settings": {
		"validate": "frappe_sso_guard.guard.site_settings.validate_website_settings",
	},
}

# Scheduled background jobs
scheduler_events = {
	"monthly": ["frappe_sso_guard.tasks.inactive_users.send_monthly_inactive_users_report"],
	"daily": ["frappe_sso_guard.tasks.api_keys.verify_active_api_key_users"],
	"cron": {"*/15 * * * *": ["frappe_sso_guard.tasks.reconciliation.run_scheduled_reconciliation"]},
}
