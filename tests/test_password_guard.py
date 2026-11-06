# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
import pytest

from frappe_sso_guard.guard import password_guard
from tests.conftest import MockDoc

pytestmark = [pytest.mark.unit, pytest.mark.security]

USER = "sso.user@example.com"
BREAK_GLASS = "break.glass@example.com"


@pytest.fixture(autouse=True)
def forced_site(mock_frappe):
	mock_frappe.conf["force_sso"] = 1
	mock_frappe.conf["sso_break_glass_user"] = BREAK_GLASS


def user_doc(name=USER, **fields):
	return MockDoc(name=name, send_welcome_email=1, **fields)


def test_password_from_the_form_is_refused(mock_frappe):
	with pytest.raises(frappe.PermissionError):
		password_guard.before_validate_user(user_doc(new_password="synthetic"))


def test_password_from_the_form_is_allowed_for_the_break_glass_account(mock_frappe):
	password_guard.before_validate_user(user_doc(BREAK_GLASS, new_password="synthetic"))


def test_password_from_a_bench_command_is_allowed(mock_frappe):
	mock_frappe.local.http_request = None
	password_guard.before_validate_user(user_doc(new_password="synthetic"))


def test_password_is_allowed_when_sso_is_not_forced(mock_frappe):
	mock_frappe.conf["force_sso"] = 0
	password_guard.before_validate_user(user_doc(new_password="synthetic"))


def test_saving_a_user_without_a_password_passes(mock_frappe):
	password_guard.before_validate_user(user_doc())


def test_welcome_email_is_switched_off_when_forced(mock_frappe):
	doc = user_doc()
	doc.__dict__["send_welcome_email"] = 1
	password_guard.before_validate_user(doc)
	assert doc.__dict__["send_welcome_email"] == 0


def test_welcome_email_is_left_alone_when_not_forced(mock_frappe):
	mock_frappe.conf["force_sso"] = 0
	doc = user_doc()
	doc.__dict__["send_welcome_email"] = 1
	password_guard.before_validate_user(doc)
	assert doc.__dict__["send_welcome_email"] == 1


def test_reset_is_refused_with_the_exception_reset_password_swallows(mock_frappe):
	with pytest.raises(frappe.DoesNotExistError):
		password_guard.validate_reset_password(user_doc())


def test_reset_is_allowed_for_the_break_glass_account(mock_frappe):
	password_guard.validate_reset_password(user_doc(BREAK_GLASS))


def test_reset_is_allowed_when_sso_is_not_forced(mock_frappe):
	mock_frappe.conf["force_sso"] = 0
	password_guard.validate_reset_password(user_doc())


def test_invitation_is_refused_when_forced(mock_frappe):
	with pytest.raises(frappe.PermissionError):
		password_guard.before_insert_user_invitation(MockDoc())


def test_invitation_is_allowed_when_not_forced(mock_frappe):
	mock_frappe.conf["force_sso"] = 0
	password_guard.before_insert_user_invitation(MockDoc())
