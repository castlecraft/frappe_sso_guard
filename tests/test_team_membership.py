# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import frappe
import pytest

from frappe_sso_guard.services import team_membership
from frappe_sso_guard.services.user_matching import SignInRefused

pytestmark = [pytest.mark.unit, pytest.mark.security]

CLAIMS = {"sub": "subject-1", "iat": 1800000000, "groups": ["/ucm/caseworkers"]}


@pytest.fixture
def audit(mocker):
	mocker.patch.object(team_membership, "notify_administrators")
	return mocker.patch.object(team_membership, "log_audit_event")


@pytest.fixture
def handler(mocker):
	handler = mocker.Mock(return_value=[])
	mocker.patch.object(team_membership, "_get_handlers", return_value=[handler])
	return handler


def _settings(mock_frappe, enabled=1, claim="groups"):
	values = {"enable_team_membership": enabled, "groups_claim": claim}
	mock_frappe.db.get_single_value.side_effect = lambda doctype, field: values[field]


def test_off_by_default_reads_no_group(mock_frappe, handler, audit):
	_settings(mock_frappe, enabled=0)
	assert team_membership.read_groups(CLAIMS, "Keycloak") is None
	audit.assert_not_called()


def test_a_site_with_no_app_holding_teams_reads_no_group(mock_frappe, mocker, audit):
	_settings(mock_frappe)
	mocker.patch.object(team_membership, "_get_handlers", return_value=[])
	assert team_membership.read_groups({"sub": "subject-1"}, "Keycloak") is None
	audit.assert_not_called()


def test_groups_come_from_the_claim_the_settings_name(mock_frappe, handler):
	_settings(mock_frappe, claim="roles_and_groups")
	claims = {"sub": "subject-1", "roles_and_groups": ["/a"], "groups": ["/b"]}
	assert team_membership.read_groups(claims, "Keycloak") == ["/a"]


def test_an_empty_list_means_no_groups_and_is_not_refused(mock_frappe, handler):
	_settings(mock_frappe)
	assert team_membership.read_groups({"sub": "subject-1", "groups": []}, "Keycloak") == []


def test_no_claim_means_no_groups_as_keycloak_sends_it(mock_frappe, handler, audit):
	_settings(mock_frappe)
	assert team_membership.read_groups({"sub": "subject-1"}, "Keycloak") == []
	audit.assert_not_called()


def test_a_claim_named_in_claim_names_is_not_taken_for_no_groups(mock_frappe, handler, audit):
	_settings(mock_frappe)
	claims = {"sub": "subject-1", "_claim_names": {"groups": "src1"}}
	with pytest.raises(SignInRefused):
		team_membership.read_groups(claims, "Keycloak")


def test_another_claim_over_its_limit_does_not_concern_the_groups(mock_frappe, handler):
	_settings(mock_frappe)
	claims = {"sub": "subject-1", "_claim_names": {"roles": "src1"}}
	assert team_membership.read_groups(claims, "Keycloak") == []


@pytest.mark.parametrize(
	"claims",
	[
		{"sub": "subject-1", "groups": "/ucm/caseworkers"},
		# What Entra ID sends when a person has too many groups for the token.
		{"oid": "o", "tid": "t", "sub": "s", "_claim_names": {"groups": "src1"}},
	],
)
def test_a_token_that_does_not_list_the_groups_is_refused_and_logged(mock_frappe, handler, audit, claims):
	_settings(mock_frappe)
	with pytest.raises(SignInRefused):
		team_membership.read_groups(claims, "Entra ID" if "oid" in claims else "Keycloak")
	assert audit.call_args.kwargs["event_type"] == "Session Refused"
	handler.assert_not_called()


def test_each_change_is_logged_with_the_group_and_the_token(mock_frappe, handler, audit):
	handler.return_value = [
		{"team": "Team A", "group": "/a", "action": "Added"},
		{"team": "Team B", "group": "/b", "action": "Removed"},
	]

	team_membership.set_teams("person@example.org", ["/a"], CLAIMS, "Keycloak")

	handler.assert_called_once_with("person@example.org", ["/a"])
	logged = [call.kwargs for call in audit.call_args_list]
	assert [row["event_type"] for row in logged] == ["Team Added", "Team Removed"]
	assert logged[0]["user"] == "person@example.org"
	assert logged[0]["idp_identifier"] == "subject-1"
	assert logged[0]["details"] == {"team": "Team A", "group": "/a", "iat": 1800000000}


def test_nothing_changing_logs_nothing(mock_frappe, handler, audit):
	team_membership.set_teams("person@example.org", ["/a"], CLAIMS, "Keycloak")
	audit.assert_not_called()


def test_teams_that_cannot_be_set_refuse_the_sign_in_and_undo_their_writes(mock_frappe, handler, audit):
	handler.side_effect = frappe.ValidationError("no")
	mock_frappe.ValidationError = frappe.ValidationError

	with pytest.raises(SignInRefused):
		team_membership.set_teams("person@example.org", ["/a"], CLAIMS, "Keycloak")

	mock_frappe.db.rollback.assert_called_once_with(save_point=team_membership.SAVEPOINT)
	assert audit.call_args.kwargs["user"] == "person@example.org"
