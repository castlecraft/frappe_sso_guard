from typing import Any, Optional

import frappe
from frappe.utils import now_datetime

from frappe_sso_guard.services.audit import log_audit_event


def get_user_immutable_id(claims: dict[str, Any], idp_type: str) -> str:
	"""Extracts the unique immutable identifier from token claims.

	- Entra ID: oid + tid (sub differs per application)
	- Keycloak / Generic OIDC: sub
	"""
	if idp_type == "Entra ID":
		oid = claims.get("oid")
		tid = claims.get("tid")
		if not oid:
			raise ValueError("Entra ID token missing 'oid' claim")
		return f"{oid}:{tid}" if tid else oid
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
		return str(edov) == "1"
	return bool(claims.get("email_verified", False))


def find_or_bind_user(
	claims: dict[str, Any],
	provider_key: str,
	idp_type: str,
) -> str:
	"""Matches the user according to the specification:

	1. If immutable identifier is known in Social Logins:
	   - Signs in.
	   - If email changed in claims, updates User.email and logs, unless another user holds that email.
	2. If unknown identifier and same email exists in Frappe:
	   - If email is verified in IdP and not bound to another identifier: bind and log.
	   - If bound to another identifier or unverified: refuse and alert admins.
	3. If unknown identifier and no user holds that email:
	   - Create User, bind Social Logins row, and log.
	"""
	immutable_id = get_user_immutable_id(claims, idp_type)
	claim_email = claims.get("email")
	first_name = claims.get("given_name") or claims.get("name") or "User"
	last_name = claims.get("family_name") or ""

	# Check for existing binding by immutable ID
	bound_user = frappe.db.get_value(
		"User Social Login",
		{"provider": provider_key, "userid": immutable_id},
		"parent",
	)

	if bound_user:
		# Existing known binding
		user_doc = frappe.get_doc("User", bound_user)
		if claim_email and user_doc.email != claim_email:
			# Email changed in IdP
			email_conflict = frappe.db.get_value(
				"User", {"email": claim_email, "name": ("!=", bound_user)}, "name"
			)
			if email_conflict:
				log_audit_event(
					event_type="Session Refused",
					status="Refused",
					user=bound_user,
					idp_identifier=immutable_id,
					details={
						"reason": "Email conflict with existing user",
						"new_email": claim_email,
						"conflicting_user": email_conflict,
					},
				)
				frappe.throw(f"Email {claim_email} is already in use by another account.")

			old_email = user_doc.email
			user_doc.email = claim_email
			user_doc.save(ignore_permissions=True)
			log_audit_event(
				event_type="Email Changed",
				status="Success",
				user=bound_user,
				idp_identifier=immutable_id,
				details={"old_email": old_email, "new_email": claim_email},
			)
		return bound_user

	# Unknown identifier: check if a user exists with claim_email
	if not claim_email:
		frappe.throw("OIDC token claims do not contain an email address.")

	existing_user_by_email = frappe.db.get_value("User", {"email": claim_email}, "name")

	if existing_user_by_email:
		# Check if already bound to another identifier
		existing_binding = frappe.db.get_value(
			"User Social Login",
			{"parent": existing_user_by_email, "provider": provider_key},
			"userid",
		)
		if existing_binding and existing_binding != immutable_id:
			log_audit_event(
				event_type="Session Refused",
				status="Refused",
				user=existing_user_by_email,
				idp_identifier=immutable_id,
				details={
					"reason": "Account already bound to another IdP identifier",
					"existing_id": existing_binding,
				},
			)
			frappe.throw("Account is already bound to another identity provider user.")

		# Check verified email requirement
		if not is_email_verified(claims, idp_type):
			log_audit_event(
				event_type="Session Refused",
				status="Refused",
				user=existing_user_by_email,
				idp_identifier=immutable_id,
				details={"reason": "IdP email is not verified, refusing account binding"},
			)
			frappe.throw("Identity provider email claim is not verified. Account binding refused.")

		# Bind to existing user
		user_doc = frappe.get_doc("User", existing_user_by_email)
		user_doc.append(
			"social_logins",
			{
				"provider": provider_key,
				"userid": immutable_id,
			},
		)
		user_doc.save(ignore_permissions=True)
		log_audit_event(
			event_type="User Bound",
			status="Success",
			user=existing_user_by_email,
			idp_identifier=immutable_id,
			details={"email": claim_email, "bound_at": now_datetime().isoformat()},
		)
		return existing_user_by_email

	# Unknown identifier and no existing user -> Create User
	new_user = frappe.get_doc(
		{
			"doctype": "User",
			"email": claim_email,
			"first_name": first_name,
			"last_name": last_name,
			"enabled": 1,
			"send_welcome_email": 0,
			"user_type": "System User",
			"social_logins": [
				{
					"provider": provider_key,
					"userid": immutable_id,
				}
			],
		}
	)
	new_user.flags.ignore_permissions = True
	new_user.flags.ignore_password_policy = True
	new_user.insert(ignore_permissions=True)

	log_audit_event(
		event_type="User Created",
		status="Success",
		user=new_user.name,
		idp_identifier=immutable_id,
		details={"email": claim_email, "created_at": now_datetime().isoformat()},
	)
	return new_user.name
