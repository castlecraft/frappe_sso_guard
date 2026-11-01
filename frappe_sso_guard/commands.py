import json

import click
import frappe


def setup_dex():
	if not frappe.db.exists("Social Login Key", "dex_local"):
		doc = frappe.get_doc(
			{
				"doctype": "Social Login Key",
				"provider_name": "dex_local",
				"base_url": "http://dex.localhost:5556/dex",
				"authorize_url": "http://dex.localhost:5556/dex/auth",
				"access_token_url": "http://dex.localhost:5556/dex/token",
				"client_id": "frappe-sso-client",
				"client_secret": "frappe_sso_secret",
				"redirect_url": "http://localhost:8000/api/method/frappe_sso_guard.api.callback.handle_callback",
				"auth_url_data": json.dumps({"response_type": "code", "scope": "openid email profile"}),
				"enable_social_login": 1,
			}
		)
		doc.insert(ignore_permissions=True)
		click.secho("Created Social Login Key: dex_local", fg="green")
	else:
		doc = frappe.get_doc("Social Login Key", "dex_local")
		doc.auth_url_data = json.dumps({"response_type": "code", "scope": "openid email profile"})
		doc.save(ignore_permissions=True)
		click.secho("Updated Social Login Key: dex_local with OIDC scopes", fg="yellow")

	settings = frappe.get_single("SSO Identity Settings")
	settings.social_login_key = "dex_local"
	settings.idp_type = "Generic OIDC"
	settings.enable_sso_guard = 1
	settings.enable_single_logout = 0
	settings.save(ignore_permissions=True)
	frappe.db.commit()
	click.secho("Configured SSO Identity Settings for Dex", fg="green")
