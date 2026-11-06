# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import json
from pathlib import Path

import frappe
import pytest

from frappe_sso_guard import commands

pytestmark = [pytest.mark.unit]

REALM_FILE = Path(__file__).parent.parent / "dev" / "keycloak" / "realm.json"
SITE_URL = "http://dev.localhost:8000"


@pytest.fixture
def realm():
	return json.loads(REALM_FILE.read_text())


@pytest.fixture
def keycloak(mocker, mock_frappe):
	mock_frappe.generate_hash.side_effect = iter(f"generated-{number}" for number in range(10))
	mocker.patch.object(commands, "get_keycloak_admin_token", return_value="admin-token")
	return mocker.patch.object(commands, "requests")


def _clients_by_id(realm):
	return {client["clientId"]: client for client in realm["clients"]}


def test_setup_keycloak_is_for_developer_mode_only(mock_frappe):
	mock_frappe.conf = frappe._dict(developer_mode=0)
	with pytest.raises(frappe.ValidationError):
		commands.setup_keycloak()


def test_setup_keycloak_needs_the_admin_password(mock_frappe, monkeypatch):
	mock_frappe.conf = frappe._dict(developer_mode=1)
	monkeypatch.delenv("KEYCLOAK_PASSWORD", raising=False)
	with pytest.raises(frappe.ValidationError):
		commands.setup_keycloak()


def test_realm_file_holds_no_credential(realm):
	text = REALM_FILE.read_text()
	assert '"secret"' not in text
	assert '"credentials"' not in text
	assert '"password"' not in text


def test_each_client_gets_its_own_new_secret(realm, keycloak):
	secrets = commands.create_keycloak_realm("http://kc", "admin", realm, SITE_URL)

	assert secrets["client_secret"] != secrets["directory_client_secret"]
	clients = _clients_by_id(realm)
	assert clients[secrets["client_id"]]["secret"] == secrets["client_secret"]
	assert clients[secrets["directory_client_id"]]["secret"] == secrets["directory_client_secret"]


def test_the_sign_in_client_allows_this_site_and_requires_pkce(realm, keycloak):
	secrets = commands.create_keycloak_realm("http://kc", "admin", realm, SITE_URL)

	client = _clients_by_id(realm)[secrets["client_id"]]
	assert f"{SITE_URL}/*" in client["redirectUris"]
	assert client["attributes"]["pkce.code.challenge.method"] == "S256"


def test_people_get_a_password_and_the_service_account_does_not(realm, keycloak):
	secrets = commands.create_keycloak_realm("http://kc", "admin", realm, SITE_URL)

	for user in realm["users"]:
		if user.get("serviceAccountClientId"):
			assert "credentials" not in user
		else:
			assert user["credentials"][0]["value"] == secrets["user_password"]


def test_the_directory_account_can_only_read_users(realm):
	account = next(user for user in realm["users"] if user.get("serviceAccountClientId"))
	assert account["clientRoles"] == {"realm-management": ["view-users"]}


def test_an_existing_realm_is_replaced(realm, keycloak):
	commands.create_keycloak_realm("http://kc", "admin", realm, SITE_URL)

	assert keycloak.delete.call_args.args[0] == f"http://kc/admin/realms/{realm['realm']}"
	assert keycloak.post.call_args.args[0] == "http://kc/admin/realms"
	assert keycloak.post.call_args.kwargs["json"] is realm
	keycloak.post.return_value.raise_for_status.assert_called_once_with()
