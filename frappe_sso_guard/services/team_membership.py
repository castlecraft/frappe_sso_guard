# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from typing import Any

import frappe
from frappe import _

from frappe_sso_guard.services.audit import log_audit_event, notify_administrators
from frappe_sso_guard.services.user_matching import SignInRefused, get_user_immutable_id

# An app holding teams names its function here: (user, groups) -> [{"team", "group", "action"}]. This app knows
# nothing of what a team is, and runs on sites that have none.
SET_TEAMS_HOOK = "sso_set_user_teams"
DEFAULT_GROUPS_CLAIM = "groups"
SAVEPOINT = "sso_set_teams"
LOG_EVENT = {"Added": "Team Added", "Removed": "Team Removed"}


def is_enabled() -> bool:
	return bool(frappe.db.get_single_value("SSO Identity Settings", "enable_team_membership"))


def read_groups(claims: dict[str, Any], idp_type: str) -> list[str] | None:
	"""The token's groups, or None where this site does not take its teams from them.

	Keycloak leaves the claim out for someone in no group, so its absence means no groups. A mapper taken off by
	mistake then costs people their group-given teams as they sign in, which fails safe, and they come back at the
	next sign-in once it is restored. Entra ID also leaves it out for someone with too many groups for a token, and
	says so in _claim_names: their groups are unknown, so the sign-in is refused rather than taking their teams.
	"""
	if not is_enabled() or not _get_handlers():
		return None

	claim = frappe.db.get_single_value("SSO Identity Settings", "groups_claim") or DEFAULT_GROUPS_CLAIM
	groups = claims.get(claim)
	if groups is None and claim not in (claims.get("_claim_names") or {}):
		return []
	if not isinstance(groups, list):
		_refuse_sign_in(
			_("Your sign-in did not say which groups you are in. Please contact your administrator."),
			get_user_immutable_id(claims, idp_type),
			reason="The token does not list the groups",
			details={"claim": claim},
		)
	return [str(group) for group in groups]


def set_teams(user: str, groups: list[str], claims: dict[str, Any], idp_type: str) -> None:
	"""Sets the user's teams from their groups and logs each change, before the session opens."""
	immutable_id = get_user_immutable_id(claims, idp_type)
	frappe.db.savepoint(SAVEPOINT)
	try:
		changes = [change for handler in _get_handlers() for change in handler(user, groups)]
	except frappe.ValidationError as e:
		frappe.db.rollback(save_point=SAVEPOINT)
		_refuse_sign_in(
			_("Your teams could not be set. Please contact your administrator."),
			immutable_id,
			reason="Teams could not be set",
			user=user,
			details={"error_type": type(e).__name__},
		)

	for change in changes:
		log_audit_event(
			event_type=LOG_EVENT[change["action"]],
			status="Success",
			user=user,
			idp_identifier=immutable_id,
			details={"team": change["team"], "group": change["group"], "iat": claims.get("iat")},
		)


def _get_handlers() -> list:
	return [frappe.get_attr(method) for method in frappe.get_hooks(SET_TEAMS_HOOK)]


def _refuse_sign_in(
	message: str,
	immutable_id: str,
	reason: str,
	user: str | None = None,
	details: dict[str, Any] | None = None,
) -> None:
	log_audit_event(
		event_type="Session Refused",
		status="Refused",
		user=user,
		idp_identifier=immutable_id,
		details={"reason": reason, **(details or {})},
	)
	notify_administrators(
		_("Single sign-on refused for {0}").format(user or immutable_id),
		_("Reason: {0}").format(reason),
	)
	raise SignInRefused(message)
