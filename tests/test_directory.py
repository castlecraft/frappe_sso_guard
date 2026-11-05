# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from unittest.mock import MagicMock

import pytest
import requests

from frappe_sso_guard.services import directory
from frappe_sso_guard.services.directory import (
	ACCOUNT_ACTIVE,
	ACCOUNT_DISABLED,
	ACCOUNT_REMOVED,
	ACCOUNT_UNKNOWN,
	DirectoryClient,
	DirectoryError,
)
from frappe_sso_guard.services.idp import SSONotConfiguredError

pytestmark = [pytest.mark.unit, pytest.mark.security]

KEYCLOAK_ISSUER = "https://idp.example.com/realms/test"
ENTRA_ISSUER = "https://login.microsoftonline.com/tenant-id/v2.0"


def response(status=200, **body):
	return MagicMock(status_code=status, json=MagicMock(return_value=body))


@pytest.fixture
def http(mocker):
	mocker.patch.object(
		directory, "get_openid_configuration", return_value={"token_endpoint": "https://t/token"}
	)
	post = mocker.patch.object(directory.requests, "post", return_value=response(access_token="token-1"))
	get = mocker.patch.object(directory.requests, "get")
	return MagicMock(post=post, get=get)


@pytest.fixture(autouse=True)
def credential(mock_frappe):
	mock_frappe.conf.update(sso_directory_client_id="reader", sso_directory_client_secret="synthetic")


def keycloak():
	return DirectoryClient("Keycloak", KEYCLOAK_ISSUER)


def entra():
	return DirectoryClient("Entra ID", ENTRA_ISSUER)


@pytest.mark.parametrize(
	"enabled, expected", [(True, ACCOUNT_ACTIVE), (False, ACCOUNT_DISABLED), (None, ACCOUNT_UNKNOWN)]
)
def test_keycloak_reads_enabled_from_the_admin_api(http, enabled, expected):
	http.get.return_value = response(enabled=enabled)
	assert keycloak().get_account_status("subject/1") == expected
	assert http.get.call_args.args[0] == "https://idp.example.com/admin/realms/test/users/subject%2F1"


@pytest.mark.parametrize("enabled, expected", [(True, ACCOUNT_ACTIVE), (False, ACCOUNT_DISABLED)])
def test_entra_reads_account_enabled_for_the_object_id_alone(http, enabled, expected):
	http.get.return_value = response(accountEnabled=enabled)
	assert entra().get_account_status("object-id:tenant-id") == expected
	assert http.get.call_args.args[0] == "https://graph.microsoft.com/v1.0/users/object-id"
	assert http.post.call_args.kwargs["data"]["scope"] == directory.GRAPH_SCOPE


def test_not_found_means_removed(http):
	http.get.return_value = response(404)
	assert keycloak().get_account_status("subject") == ACCOUNT_REMOVED


@pytest.mark.parametrize("status", [403, 429, 500, 503])
def test_any_other_answer_says_nothing_about_the_account(http, status):
	http.get.return_value = response(status)
	with pytest.raises(DirectoryError):
		keycloak().get_account_status("subject")


def test_expired_token_is_replaced_once(http):
	http.get.side_effect = [response(401), response(enabled=True)]
	assert keycloak().get_account_status("subject") == ACCOUNT_ACTIVE
	assert http.post.call_count == 2


def test_token_still_refused_after_replacing_it_is_an_error(http):
	http.get.side_effect = [response(401), response(401)]
	with pytest.raises(DirectoryError):
		keycloak().get_account_status("subject")


def test_token_is_reused_between_accounts(http):
	http.get.return_value = response(enabled=True)
	client = keycloak()
	client.get_account_status("one")
	client.get_account_status("two")
	assert http.post.call_count == 1


def test_refused_credential_is_an_error(http):
	http.post.return_value = response(401)
	with pytest.raises(DirectoryError):
		keycloak().get_account_status("subject")


def test_unreachable_provider_is_an_error(http):
	http.get.side_effect = requests.ConnectionError()
	with pytest.raises(DirectoryError):
		keycloak().get_account_status("subject")


def test_missing_credential_is_refused(http, mock_frappe):
	mock_frappe.conf.clear()
	with pytest.raises(SSONotConfiguredError):
		keycloak()


def test_generic_provider_has_no_directory(http):
	with pytest.raises(SSONotConfiguredError):
		DirectoryClient("Generic OIDC", KEYCLOAK_ISSUER)


def test_issuer_without_a_realm_is_refused(http):
	with pytest.raises(SSONotConfiguredError):
		DirectoryClient("Keycloak", "https://idp.example.com/other")
