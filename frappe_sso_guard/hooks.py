app_name = "frappe_sso_guard"
app_title = "Frappe SSO Guard"
app_publisher = "ICRC / Castlecraft"
app_description = "Frappe SSO Guard with strict OIDC enforcement"
app_email = "support@castlecraft.in"
app_license = "mit"

# Minimal, essential hooks
on_login = "frappe_sso_guard.guard.session_guard.enforce_session_guard"

# Scheduled background jobs
scheduler_events = {
	"monthly": ["frappe_sso_guard.tasks.inactive_users.send_monthly_inactive_users_report"],
	"daily": ["frappe_sso_guard.tasks.api_keys.verify_active_api_key_users"],
}

# Auto-prune log clearing registration
default_log_clearing_doctypes = {
	"SSO Identity Assignment Log": 90,
}
