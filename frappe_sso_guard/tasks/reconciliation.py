# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import math

import frappe
import requests
from frappe import _
from frappe.sessions import clear_sessions
from frappe.utils import now_datetime, time_diff_in_seconds

from frappe_sso_guard.guard.session_guard import get_break_glass_user
from frappe_sso_guard.services.audit import log_audit_event, notify_administrators
from frappe_sso_guard.services.directory import (
	ACCOUNT_DISABLED,
	ACCOUNT_REMOVED,
	ACCOUNT_UNKNOWN,
	DirectoryClient,
	DirectoryError,
)
from frappe_sso_guard.services.idp import SSONotConfiguredError, get_sign_in_config

JOB_ID = "frappe_sso_guard_reconciliation"
JOB_TIMEOUT_SECONDS = 3600
SCHEDULE_MINUTES = {"Every 15 Minutes": 15, "Hourly": 60, "Daily": 1440}
# The job starts a little after its cron time, so an exact comparison would skip every other run.
SCHEDULE_SLACK_SECONDS = 120
DEFAULT_MAX_DISABLE_PERCENT = 10
# On a small site one person leaving is a large share, and no reason to stop.
ALWAYS_ALLOWED_DISABLES = 5


def enqueue_reconciliation() -> None:
	frappe.enqueue(
		"frappe_sso_guard.tasks.reconciliation.reconcile_users",
		queue="long",
		timeout=JOB_TIMEOUT_SECONDS,
		job_id=JOB_ID,
		deduplicate=True,
	)


def run_scheduled_reconciliation() -> None:
	"""Called every 15 minutes, and starts a run when the schedule in SSO Identity Settings is due."""
	settings = frappe.get_single("SSO Identity Settings")
	minutes = SCHEDULE_MINUTES.get(settings.reconciliation_frequency)
	if not settings.enable_reconciliation or not minutes:
		return

	last_run = settings.last_reconciliation
	if last_run and time_diff_in_seconds(now_datetime(), last_run) < minutes * 60 - SCHEDULE_SLACK_SECONDS:
		return

	enqueue_reconciliation()


def reconcile_users() -> dict[str, int]:
	"""Disables in Frappe each bound user the identity provider has disabled or removed.

	Every account is read before anything changes, so that a provider failing halfway, or answering
	wrongly for everyone, leaves all users as they were.
	"""
	settings = frappe.get_single("SSO Identity Settings")
	frappe.db.set_single_value("SSO Identity Settings", "last_reconciliation", now_datetime())

	summary = {"checked": 0, "disabled": 0, "failed": 0, "unknown": 0}
	try:
		config = get_sign_in_config()
		client = DirectoryClient(config["idp_type"], config["sso_issuer"])
		leavers = []
		for row in get_bound_users(config["social_login_key"], get_break_glass_user()):
			status = client.get_account_status(row.userid)
			summary["checked"] += 1
			if status in (ACCOUNT_DISABLED, ACCOUNT_REMOVED):
				leavers.append((row, status))
			elif status == ACCOUNT_UNKNOWN:
				summary["unknown"] += 1
	except (SSONotConfiguredError, DirectoryError, ValueError, requests.RequestException) as e:
		_report_abort(str(e), summary)
		return summary

	max_percent = settings.reconciliation_max_disable_percent or DEFAULT_MAX_DISABLE_PERCENT
	limit = max(ALWAYS_ALLOWED_DISABLES, math.ceil(summary["checked"] * max_percent / 100))
	if len(leavers) > limit:
		_report_abort(
			f"{len(leavers)} of {summary['checked']} users would be disabled, above the limit", summary
		)
		return summary

	for row, status in leavers:
		if disable_user(row.user, row.userid, status):
			summary["disabled"] += 1
		else:
			summary["failed"] += 1

	log_audit_event(event_type="Reconciliation Run", status="Success", details=summary)
	if summary["disabled"] or summary["failed"]:
		notify_administrators(
			_("Single sign-on: reconciliation disabled {0} users").format(summary["disabled"]),
			_("{0} users checked, {1} disabled, {2} could not be disabled.").format(
				summary["checked"], summary["disabled"], summary["failed"]
			),
		)
	return summary


def get_bound_users(provider: str, excluded_user: str | None = None) -> list[frappe._dict]:
	"""The enabled users bound to this provider, without the standard users and the excluded one."""
	login = frappe.qb.DocType("User Social Login")
	user = frappe.qb.DocType("User")
	excluded = [*frappe.STANDARD_USERS, *([excluded_user] if excluded_user else [])]
	return (
		frappe.qb.from_(login)
		.join(user)
		.on(user.name == login.parent)
		.select(login.parent.as_("user"), login.userid)
		.where(
			(login.provider == provider)
			& (login.parenttype == "User")
			& (user.enabled == 1)
			& (user.name.notin(excluded))
		)
		.run(as_dict=True)
	)


def disable_user(user: str, idp_identifier: str, account_status: str) -> bool:
	"""Disables the User, not deletes it, so that their records and audit trail stay."""
	savepoint = "sso_disable_user"
	frappe.db.savepoint(savepoint)
	try:
		doc = frappe.get_doc("User", user)
		doc.enabled = 0
		# Runs in a job on the identity provider's word, whoever launched it.
		doc.save(ignore_permissions=True)
	except frappe.ValidationError as e:
		# Frappe refuses to disable the last System Manager, for one.
		frappe.db.rollback(save_point=savepoint)
		log_audit_event(
			event_type="User Disabled",
			status="Error",
			user=user,
			idp_identifier=idp_identifier,
			details={"account_status": account_status, "error": str(e)},
		)
		return False

	# User.save ends the sessions only when a login manager exists, and a job has none.
	clear_sessions(user=user, force=True)
	log_audit_event(
		event_type="User Disabled",
		status="Warning",
		user=user,
		idp_identifier=idp_identifier,
		details={"account_status": account_status},
	)
	return True


def _report_abort(reason: str, summary: dict[str, int]) -> None:
	log_audit_event(
		event_type="Reconciliation Aborted", status="Error", details={"reason": reason, **summary}
	)
	notify_administrators(
		_("Single sign-on: reconciliation stopped"),
		_("No user was disabled. Reason: {0}").format(reason),
	)
