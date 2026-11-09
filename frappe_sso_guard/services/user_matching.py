# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from typing import Any

import frappe
from frappe import _
from frappe.integrations.doctype.social_login_key.social_login_key import provider_allows_signup
from frappe.utils import now_datetime

from frappe_sso_guard.services.audit import log_audit_event, notify_administrators


class SignInRefused(Exception):
	"""The token is valid but must not open a session. Its message is shown to the visitor."""


def get_user_immutable_id(claims: dict[str, Any], idp_type: str) -> str:
	"""Extracts the unique immutable identifier from token claims.

	- Entra ID: oid + tid (sub differs per application)
	- Keycloak / Generic OIDC: sub
	"""
	if idp_type == "Entra ID":
		oid = claims.get("oid")
		tid = claims.get("tid")
		if not (oid and tid):
			raise ValueError("Entra ID token missing 'oid' or 'tid' claim")
		return f"{oid}:{tid}"
	else:
		sub = claims.get("sub")
		if not sub:
			raise ValueError("OIDC token missing 'sub' claim")
		return str(sub)


def is_email_verified(claims: dict[str, Any], idp_type: str) -> bool:
	"""Checks whether the email claim was verified by the identity provider.

	- Keycloak / OIDC standard: email_verified is True
	- Entra ID: xms_edov (email domain owner verified) is "1" or 1
	"""
	if idp_type == "Entra ID":
		edov = claims.get("xms_edov")
		return str(edov) == "1" or edov is True
	return claims.get("email_verified") is True


def find_or_bind_user(
	claims: dict[str, Any],
	provider_key: str,
	idp_type: str,
) -> str:
	"""Matches the user by the identity provider's immutable identifier, never by email alone:

	1. Known identifier: signs in, whatever the email claim says.
	2. Unknown identifier, an account holds the email: binds only when the identity provider
	   verified the email and the account has no other identifier.
	3. Unknown identifier, no account holds the email: creates the User, if sign-ups are allowed.
	"""
	immutable_id = get_user_immutable_id(claims, idp_type)
	_check_mfa(claims, immutable_id)
	claim_email = (claims.get("email") or "").strip().lower()

	bound_user = frappe.db.get_value(
		"User Social Login",
		{"provider": provider_key, "userid": immutable_id, "parenttype": "User"},
		"parent",
	)
	if bound_user:
		_check_can_sign_in(bound_user, immutable_id)
		_note_changed_email(bound_user, claim_email, immutable_id)
		return bound_user

	if not claim_email:
		_refuse(
			_("Your identity provider account has no email address. Please contact your administrator."),
			immutable_id,
			reason="Unknown identifier and no email claim",
		)

	existing_user = frappe.db.get_value("User", {"email": claim_email}, "name")
	if existing_user:
		return _bind_existing_user(existing_user, claims, provider_key, idp_type, immutable_id, claim_email)

	return _create_user(claims, provider_key, immutable_id, claim_email)


def _check_mfa(claims: dict[str, Any], immutable_id: str) -> None:
	"""Refuses a token that does not show the MFA the site config asks for.

	The identity provider enforces MFA; this catches a sign-in flow changed there, or a client taken
	out of it. The setting is in the site config so that a System Manager cannot turn it off.
	"""
	conf = frappe.conf or {}
	accepted = conf.get("sso_mfa_values")
	if not accepted:
		return

	claim = conf.get("sso_mfa_claim") or "acr"
	presented = claims.get(claim)
	presented = presented if isinstance(presented, list) else [presented]
	accepted = accepted if isinstance(accepted, list) else [accepted]
	if not {str(value) for value in presented} & {str(value) for value in accepted}:
		_refuse(
			_("Your sign-in did not use multi-factor authentication. Please contact your administrator."),
			immutable_id,
			reason="The token does not show the required multi-factor authentication",
			details={"claim": claim},
			notify=True,
		)


def _check_can_sign_in(user: str, immutable_id: str) -> None:
	# Administrator has no identity provider account: a row binding it could only be a mistake or
	# an attack. Frappe also refuses a disabled user, but with a raw error instead of a page.
	if user in frappe.STANDARD_USERS:
		_refuse(
			_("This account cannot sign in through the identity provider."),
			immutable_id,
			user=user,
			reason="A standard user cannot sign in through the identity provider",
			notify=True,
		)

	if not frappe.db.get_value("User", user, "enabled"):
		_refuse(
			_("This account is disabled. Please contact your administrator."),
			immutable_id,
			user=user,
			reason="Account is disabled",
		)


def _note_changed_email(user: str, claim_email: str, immutable_id: str) -> None:
	if not claim_email or claim_email == user:
		return

	conflicting_user = frappe.db.get_value("User", {"email": claim_email, "name": ("!=", user)}, "name")
	if conflicting_user:
		_refuse(
			_("Your email address is already used by another account. Please contact your administrator."),
			immutable_id,
			user=user,
			reason="Email conflict with existing user",
			details={"new_email": claim_email, "conflicting_user": conflicting_user},
			notify=True,
		)

	# A User's name is its email and User.validate resets the email to the name, so the only real
	# change is a rename. That rewrites owner and modified_by in every table, far too heavy to run
	# during a sign-in on a site of this size, so the person signs in and an administrator decides.
	log_audit_event(
		event_type="Email Changed",
		status="Warning",
		user=user,
		idp_identifier=immutable_id,
		details={"old_email": user, "new_email": claim_email, "applied": False},
	)
	notify_administrators(
		_("Single sign-on: email changed for {0}").format(user),
		_("The identity provider now gives {0} as the email of {1}. The account was not renamed.").format(
			claim_email, user
		),
	)


def _bind_existing_user(
	user: str,
	claims: dict[str, Any],
	provider_key: str,
	idp_type: str,
	immutable_id: str,
	claim_email: str,
) -> str:
	_check_can_sign_in(user, immutable_id)

	existing_binding = frappe.db.get_value(
		"User Social Login",
		{"parent": user, "parenttype": "User", "provider": provider_key},
		"userid",
	)
	if existing_binding:
		_refuse(
			_("This account is already linked to another identity. Please contact your administrator."),
			immutable_id,
			user=user,
			reason="Account already bound to another identifier",
			details={"existing_id": existing_binding},
			notify=True,
		)

	if not is_email_verified(claims, idp_type):
		_refuse(
			_(
				"Your identity provider has not verified your email address. Please contact your administrator."
			),
			immutable_id,
			user=user,
			reason="Email not verified, refusing to bind",
			notify=True,
		)

	user_doc = frappe.get_doc("User", user)
	user_doc.append("social_logins", {"provider": provider_key, "userid": immutable_id})
	# No session exists yet, so this runs as Guest: the signed token authorises the change.
	user_doc.save(ignore_permissions=True)
	log_audit_event(
		event_type="User Bound",
		status="Success",
		user=user,
		idp_identifier=immutable_id,
		details={"email": claim_email, "bound_at": now_datetime().isoformat(), "iat": claims.get("iat")},
	)
	return user


def _create_user(claims: dict[str, Any], provider_key: str, immutable_id: str, claim_email: str) -> str:
	if not provider_allows_signup(provider_key):
		_refuse(
			_("You do not have an account on this site. Please contact your administrator."),
			immutable_id,
			reason="Sign-ups are not allowed on this Social Login Key",
			details={"email": claim_email},
		)

	new_user = frappe.get_doc(
		{
			"doctype": "User",
			"email": claim_email,
			"first_name": claims.get("given_name") or claims.get("name") or claim_email,
			"last_name": claims.get("family_name") or "",
			"enabled": 1,
			"send_welcome_email": 0,
			"user_type": "Website User",
			"social_logins": [{"provider": provider_key, "userid": immutable_id}],
		}
	)
	new_user.flags.no_welcome_mail = True
	# No session exists yet, so this runs as Guest. The account holds no role until one is given.
	new_user.insert(ignore_permissions=True)

	log_audit_event(
		event_type="User Created",
		status="Success",
		user=new_user.name,
		idp_identifier=immutable_id,
		details={"email": claim_email, "created_at": now_datetime().isoformat(), "iat": claims.get("iat")},
	)
	return new_user.name


def _refuse(
	message: str,
	immutable_id: str,
	reason: str,
	user: str | None = None,
	details: dict[str, Any] | None = None,
	notify: bool = False,
) -> None:
	log_audit_event(
		event_type="Session Refused",
		status="Refused",
		user=user,
		idp_identifier=immutable_id,
		details={"reason": reason, **(details or {})},
	)
	if notify:
		notify_administrators(
			_("Single sign-on refused for {0}").format(user or immutable_id),
			_("Reason: {0}").format(reason),
		)
	raise SignInRefused(message)
