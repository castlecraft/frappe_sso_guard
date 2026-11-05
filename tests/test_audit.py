# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import json
from datetime import datetime

import pytest

from frappe_sso_guard.services import audit

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def fixed_time(mocker):
	# The real now_datetime reads the site's time zone, which needs a site.
	mocker.patch.object(audit, "now_datetime", return_value=datetime(2026, 1, 15, 9, 30))


def logged_event(logger_method):
	return json.loads(logger_method.call_args.args[0])


def test_event_is_logged_and_persisted(mock_frappe):
	audit.log_audit_event("Sign In", "Success", user="sso.user@example.com", ip_address="192.0.2.1")

	logger = mock_frappe.logger.return_value
	assert logged_event(logger.info)["event_type"] == "Sign In"
	assert logged_event(logger.info)["ip_address"] == "192.0.2.1"

	record = mock_frappe.get_doc.call_args.args[0]
	assert record["doctype"] == "SSO Identity Assignment Log"
	assert record["user"] == "sso.user@example.com"
	mock_frappe.get_doc.return_value.insert.assert_called_once_with(ignore_permissions=True)


@pytest.mark.parametrize("status", ["Refused", "Error"])
def test_failed_events_are_logged_as_warnings(mock_frappe, status):
	audit.log_audit_event("Sign In", status)

	logger = mock_frappe.logger.return_value
	assert logged_event(logger.warning)["status"] == status
	logger.info.assert_not_called()


@pytest.mark.security
def test_unauthenticated_events_are_not_persisted(mock_frappe):
	audit.log_audit_event("Sign In", "Refused", persist=False)

	mock_frappe.logger.return_value.warning.assert_called_once()
	mock_frappe.get_doc.assert_not_called()


def test_request_ip_is_used_when_none_is_passed(mock_frappe):
	mock_frappe.local.request_ip = "192.0.2.2"
	audit.log_audit_event("Sign In", "Success")
	assert mock_frappe.get_doc.call_args.args[0]["ip_address"] == "192.0.2.2"


def test_logger_failure_falls_back_to_stdout(mock_frappe, capsys):
	mock_frappe.logger.side_effect = RuntimeError("logger unavailable")

	audit.log_audit_event("Sign In", "Success")

	assert '"event_type": "Sign In"' in capsys.readouterr().out
	mock_frappe.get_doc.assert_called_once()


def test_database_failure_does_not_fail_the_sign_in(mock_frappe):
	mock_frappe.get_doc.return_value.insert.side_effect = RuntimeError("database unavailable")

	audit.log_audit_event("Sign In", "Success")

	mock_frappe.log_error.assert_called_once()


def test_administrators_are_mailed_with_the_message_escaped(mock_frappe):
	mock_frappe.db.get_single_value.return_value = "first@example.com, second@example.com,"

	audit.notify_administrators("Subject", "<script>claim</script>")

	mail = mock_frappe.sendmail.call_args.kwargs
	assert mail["recipients"] == ["first@example.com", "second@example.com"]
	assert "<script>" not in mail["message"]


@pytest.mark.parametrize("recipients", [None, "", " , "])
def test_no_mail_without_recipients(mock_frappe, recipients):
	mock_frappe.db.get_single_value.return_value = recipients

	audit.notify_administrators("Subject", "Message")

	mock_frappe.sendmail.assert_not_called()


def test_mail_failure_is_logged_and_not_raised(mock_frappe):
	mock_frappe.db.get_single_value.return_value = "first@example.com"
	mock_frappe.sendmail.side_effect = RuntimeError("mail unavailable")

	audit.notify_administrators("Subject", "Message")

	mock_frappe.log_error.assert_called_once()
