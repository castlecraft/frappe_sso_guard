# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
import requests
from frappe import _

from frappe_sso_guard.guard.api_key_guard import API_KEY_ALLOWED_FIELD
from frappe_sso_guard.guard.session_guard import ADMIN_ROLES
from frappe_sso_guard.services.audit import log_audit_event, notify_administrators
from frappe_sso_guard.services.directory import (
	ACCOUNT_DISABLED,
	ACCOUNT_REMOVED,
	DirectoryClient,
	DirectoryError,
)
from frappe_sso_guard.services.idp import SSONotConfiguredError, get_provider_key, get_sign_in_config
from frappe_sso_guard.tasks.reconciliation import disable_user


def verify_active_api_key_users():
	"""Daily check of the Users holding an API key, each one a standing way around the identity provider.

	A key the guard refused can still appear through a bench command or a data import, so its rules
	are checked again. A User the identity provider has disabled is disabled here, which ends the key.
	"""
	holders = frappe.get_all(
		"User",
		filters={"enabled": 1, "api_key": ("is", "set")},
		fields=["name", "restrict_ip", API_KEY_ALLOWED_FIELD],
	)

	alerts = 0
	for holder in holders:
		for issue in _get_issues(holder):
			_alert(holder.name, issue)
			alerts += 1

	alerts += _disable_holders_gone_from_identity_provider([holder.name for holder in holders])

	if alerts:
		notify_administrators(
			_("Single sign-on: {0} API key alerts").format(alerts),
			_("See the API Key Alert entries in the SSO Identity Assignment Log."),
		)


def _get_issues(holder: frappe._dict) -> list[str]:
	issues = []
	if not holder.get(API_KEY_ALLOWED_FIELD):
		issues.append("User holds an API key without being flagged for one")
	if not holder.restrict_ip:
		issues.append("User holds an API key without Restrict IP")
	if set(frappe.get_roles(holder.name)) & set(ADMIN_ROLES):
		issues.append("User holds an API key and an administrative role")
	return issues


def _disable_holders_gone_from_identity_provider(holders: list[str]) -> int:
	provider = get_provider_key()
	if not holders or not provider:
		return 0

	bound = frappe.get_all(
		"User Social Login",
		filters={"parenttype": "User", "provider": provider, "parent": ("in", holders)},
		fields=["parent", "userid"],
	)
	if not bound:
		return 0

	try:
		config = get_sign_in_config()
		client = DirectoryClient(config["idp_type"], config["sso_issuer"])
	except (SSONotConfiguredError, ValueError, requests.RequestException) as e:
		_alert(None, f"API key holders could not be checked: {e}")
		return 1

	alerts = 0
	for row in bound:
		try:
			status = client.get_account_status(row.userid)
		except DirectoryError as e:
			_alert(row.parent, f"Could not be checked: {e}")
			alerts += 1
			continue

		if status in (ACCOUNT_DISABLED, ACCOUNT_REMOVED) and not disable_user(row.parent, row.userid, status):
			_alert(row.parent, "Gone from the identity provider but could not be disabled")
			alerts += 1
	return alerts


def _alert(user: str | None, issue: str) -> None:
	log_audit_event(event_type="API Key Alert", status="Warning", user=user, details={"issue": issue})
