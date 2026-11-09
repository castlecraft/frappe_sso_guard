# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from unittest.mock import MagicMock

import frappe
import pytest

from frappe_sso_guard.guard import session_guard
from frappe_sso_guard.guard.session_guard import enforce_session_guard, is_web_request

pytestmark = [pytest.mark.unit, pytest.mark.security]

BREAK_GLASS = "break.glass@example.com"


@pytest.fixture(autouse=True)
def audit(mocker):
	"""Stands in for the audit calls, which have their own tests and read the site's time zone."""
	log = mocker.patch.object(session_guard, "log_audit_event")
	notify = mocker.patch.object(session_guard, "notify_administrators")
	return MagicMock(log=log, notify=notify)


@pytest.fixture(autouse=True)
def break_glass_setting(mock_frappe):
	mock_frappe.conf["sso_break_glass_user"] = BREAK_GLASS
	mock_frappe.db.get_single_value.return_value = "test_provider"
	mock_frappe.db.exists.return_value = False
	mock_frappe.get_roles.return_value = ["Guest", "Desk User"]


def login_as(user="sso.user@example.com"):
	return MagicMock(user=user)


def test_guest_is_allowed(mock_frappe):
	mock_frappe.conf["force_sso"] = 1
	enforce_session_guard(login_as("Guest"))


def test_without_a_request_is_allowed_logged_and_notified(mock_frappe, audit):
	mock_frappe.conf["force_sso"] = 1
	mock_frappe.local.http_request = None

	enforce_session_guard(login_as("Administrator"))

	assert audit.log.call_args.kwargs["event_type"] == "Admin CLI Bypass"
	assert audit.log.call_args.kwargs["user"] == "Administrator"
	audit.notify.assert_called_once()


def test_login_authorized_by_the_callback_is_allowed(mock_frappe):
	mock_frappe.conf["force_sso"] = 1
	mock_frappe.flags.oidc_session_authorized = True
	enforce_session_guard(login_as())


def test_other_web_login_is_refused_when_sso_is_forced(mock_frappe):
	mock_frappe.conf["force_sso"] = 1
	with pytest.raises(frappe.PermissionError):
		enforce_session_guard(login_as())


def test_login_inside_http_request_is_refused_when_sso_is_forced(mock_frappe):
	"""A login runs before http_request is assigned, with only request_ip set."""
	mock_frappe.conf["force_sso"] = 1
	mock_frappe.local.http_request = None
	mock_frappe.local.request_ip = "192.0.2.1"
	with pytest.raises(frappe.PermissionError):
		enforce_session_guard(login_as())


def test_sso_is_forced_when_the_setting_is_absent(mock_frappe):
	with pytest.raises(frappe.PermissionError):
		enforce_session_guard(login_as())


@pytest.mark.parametrize("value", [0, "0"])
def test_other_web_login_is_allowed_when_sso_is_not_forced(mock_frappe, value):
	mock_frappe.conf["force_sso"] = value
	enforce_session_guard(login_as())


def test_bound_user_is_refused_even_when_sso_is_not_forced(mock_frappe):
	mock_frappe.conf["force_sso"] = 0
	mock_frappe.db.exists.return_value = True
	with pytest.raises(frappe.PermissionError):
		enforce_session_guard(login_as())


@pytest.mark.parametrize("role", ["System Manager", "UCM Administrator", "UCM Data Manager", "Administrator"])
def test_admin_role_is_refused_even_when_sso_is_not_forced(mock_frappe, role):
	mock_frappe.conf["force_sso"] = 0
	mock_frappe.get_roles.return_value = ["Desk User", role]
	with pytest.raises(frappe.PermissionError):
		enforce_session_guard(login_as())


def test_break_glass_account_is_allowed_when_sso_is_not_forced_though_an_administrator(mock_frappe, audit):
	mock_frappe.conf["force_sso"] = 0
	mock_frappe.get_roles.return_value = ["System Manager"]

	enforce_session_guard(login_as(BREAK_GLASS))

	assert audit.log.call_args.kwargs["event_type"] == "Break-Glass Login"


def test_refusal_is_logged_notified_and_committed_before_the_rollback(mock_frappe, audit):
	mock_frappe.conf["force_sso"] = 1
	mock_frappe.in_test = False

	with pytest.raises(frappe.PermissionError):
		enforce_session_guard(login_as())

	assert audit.log.call_args.kwargs["event_type"] == "Session Refused"
	audit.notify.assert_called_once()
	mock_frappe.db.commit.assert_called_once()


def test_break_glass_account_is_allowed_logged_and_notified(mock_frappe, audit):
	mock_frappe.conf["force_sso"] = 1

	enforce_session_guard(login_as(BREAK_GLASS))

	assert audit.log.call_args.kwargs["event_type"] == "Break-Glass Login"
	audit.notify.assert_called_once()


def test_no_break_glass_account_set_allows_nobody(mock_frappe):
	mock_frappe.conf["force_sso"] = 1
	del mock_frappe.conf["sso_break_glass_user"]
	with pytest.raises(frappe.PermissionError):
		enforce_session_guard(login_as("Administrator"))


@pytest.mark.parametrize(
	"http_request, request_ip, expected",
	[(None, None, False), (None, "192.0.2.1", True), (MagicMock(), None, True)],
)
def test_is_web_request(mock_frappe, http_request, request_ip, expected):
	mock_frappe.local.http_request = http_request
	mock_frappe.local.request_ip = request_ip
	assert is_web_request() is expected
