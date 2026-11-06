# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
import pytest

from frappe_sso_guard.guard import site_settings
from tests.conftest import MockDoc

pytestmark = [pytest.mark.unit, pytest.mark.security]


@pytest.fixture(autouse=True)
def forced_site(mock_frappe, mocker):
	mock_frappe.conf["force_sso"] = 1
	mock_frappe.get_all.return_value = []
	return mocker.patch.object(site_settings, "log_audit_event")


def test_web_save_turning_the_email_link_on_is_refused(mock_frappe):
	with pytest.raises(frappe.ValidationError):
		site_settings.validate_system_settings(MockDoc(login_with_email_link=1))


def test_web_save_allowing_sign_ups_is_refused(mock_frappe):
	with pytest.raises(frappe.ValidationError):
		site_settings.validate_website_settings(MockDoc(disable_signup=0))


def test_aligned_settings_can_be_saved(mock_frappe):
	site_settings.validate_system_settings(MockDoc(login_with_email_link=0))
	site_settings.validate_website_settings(MockDoc(disable_signup=1))


def test_bench_command_is_left_alone(mock_frappe):
	mock_frappe.local.http_request = None
	site_settings.validate_system_settings(MockDoc(login_with_email_link=1))
	site_settings.validate_website_settings(MockDoc(disable_signup=0))


def test_site_not_forced_is_left_alone(mock_frappe):
	mock_frappe.conf["force_sso"] = 0
	site_settings.validate_system_settings(MockDoc(login_with_email_link=1))
	site_settings.validate_website_settings(MockDoc(disable_signup=0))


def test_align_changes_nothing_when_not_forced(mock_frappe, forced_site):
	mock_frappe.conf["force_sso"] = 0
	site_settings.align_site_with_force_sso()
	mock_frappe.db.set_single_value.assert_not_called()
	mock_frappe.db.set_value.assert_not_called()
	forced_site.assert_not_called()


def test_align_corrects_settings_and_expires_invitations_and_logs_it(mock_frappe, forced_site):
	mock_frappe.db.get_single_value.side_effect = lambda doctype, fieldname: {
		"login_with_email_link": 1,
		"disable_signup": 0,
	}[fieldname]
	mock_frappe.get_all.return_value = ["invitation-1"]

	site_settings.align_site_with_force_sso()

	mock_frappe.db.set_single_value.assert_any_call("System Settings", "login_with_email_link", 0)
	mock_frappe.db.set_single_value.assert_any_call("Website Settings", "disable_signup", 1)
	mock_frappe.db.set_value.assert_called_once_with("User Invitation", "invitation-1", "status", "Expired")
	forced_site.assert_called_once()
	assert forced_site.call_args.kwargs["details"] == {
		"settings": ["login_with_email_link", "disable_signup"],
		"invitations_expired": 1,
	}


def test_align_logs_nothing_on_an_aligned_site(mock_frappe, forced_site):
	mock_frappe.db.get_single_value.side_effect = lambda doctype, fieldname: {
		"login_with_email_link": 0,
		"disable_signup": 1,
	}[fieldname]

	site_settings.align_site_with_force_sso()

	mock_frappe.db.set_single_value.assert_not_called()
	forced_site.assert_not_called()
