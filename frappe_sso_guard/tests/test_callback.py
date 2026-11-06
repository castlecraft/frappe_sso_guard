# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import base64
import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import frappe
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from frappe.auth import CookieManager, LoginManager
from frappe.sessions import get_expiry_in_seconds
from frappe.tests import IntegrationTestCase
from frappe.utils import set_request
from frappe.utils.oauth import create_oauth_state
from jwt.algorithms import RSAAlgorithm

from frappe_sso_guard.api.callback import FLOW_COOKIE_PREFIX, handle_callback, start
from frappe_sso_guard.services import idp, team_membership

PROVIDER_KEY = "test_sso_provider"
CLIENT_ID = "test-client"
UNTRUSTED_TOKEN_URL = "https://untrusted.example.org/token"
PAYLOAD = "<img src=x onerror=alert(1)>"
SSO_USER = "sso.person@example.org"
FIXTURES = Path(__file__).parent / "fixtures"


def _generate_key():
	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


SIGNING_KEY = _generate_key()
OTHER_KEY = _generate_key()


def _pem(key) -> bytes:
	return key.private_bytes(
		serialization.Encoding.PEM,
		serialization.PrivateFormat.PKCS8,
		serialization.NoEncryption(),
	)


class MockIdentityProvider:
	"""Answers discovery, JWKS and token requests as Keycloak or Entra ID do, with real signatures.

	The token endpoint enforces PKCE, so a wrong verifier fails the way a real provider fails it.
	"""

	def __init__(self, issuer: str, jwks_uri: str, identity_claims: dict):
		self.issuer = issuer
		self.jwks_uri = jwks_uri
		self.identity_claims = identity_claims
		self.authorize_params: dict = {}
		self.token_urls: list[str] = []
		self.claim_overrides: dict = {}
		self.sign_with = dict(key=_pem(SIGNING_KEY), algorithm="RS256")

	def discovery(self) -> dict:
		return {
			"issuer": self.issuer,
			"authorization_endpoint": f"{self.issuer}/authorize",
			"token_endpoint": f"{self.issuer}/token",
			"jwks_uri": self.jwks_uri,
		}

	def jwks(self) -> dict:
		key = json.loads(RSAAlgorithm.to_jwk(SIGNING_KEY.public_key()))
		key.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
		return {"keys": [key]}

	def id_token(self) -> str:
		now = int(time.time())
		claims = {
			"iss": self.issuer,
			"aud": CLIENT_ID,
			"iat": now,
			"exp": now + 300,
			"nonce": self.authorize_params.get("nonce"),
			**self.identity_claims,
			**self.claim_overrides,
		}
		claims = {name: value for name, value in claims.items() if value is not None}
		return jwt.encode(claims, headers={"kid": "test-key"}, **self.sign_with)

	def get(self, url, timeout=None):
		return self._response(self.discovery())

	def post(self, url, data=None, timeout=None):
		self.token_urls.append(url)
		digest = hashlib.sha256(data["code_verifier"].encode()).digest()
		challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
		if challenge != self.authorize_params.get("code_challenge"):
			return self._response({}, failed=True)
		return self._response({"id_token": self.id_token()})

	def _response(self, body: dict, failed: bool = False):
		response = MagicMock()
		response.json.return_value = body
		response.raise_for_status.side_effect = requests.HTTPError("400") if failed else None
		return response


def _keycloak(**claims) -> MockIdentityProvider:
	issuer = "https://keycloak.example.org/realms/test"
	return MockIdentityProvider(
		issuer,
		f"{issuer}/protocol/openid-connect/certs",
		{"sub": "kc-subject-1", "email": "sso.person@example.org", "email_verified": True, **claims},
	)


def _entra(**claims) -> MockIdentityProvider:
	return MockIdentityProvider(
		"https://login.microsoftonline.com/tenant-1/v2.0",
		"https://login.microsoftonline.com/tenant-1/discovery/v2.0/keys",
		{
			"sub": "differs-per-application",
			"oid": "object-1",
			"tid": "tenant-1",
			"email": "sso.person@example.org",
			"xms_edov": "1",
			**claims,
		},
	)


class TestMockMatchesKeycloak(IntegrationTestCase):
	"""The fixtures are what a real Keycloak answered, so the mock cannot drift into something else."""

	def _fixture(self, name):
		return json.loads((FIXTURES / name).read_text())

	def test_every_claim_the_mock_signs_is_one_keycloak_sends_with_the_same_type(self):
		real = self._fixture("keycloak_id_token_claims.json")
		mock = jwt.decode(_keycloak().id_token(), options={"verify_signature": False})
		for name, value in mock.items():
			self.assertIn(name, real)
			self.assertIs(type(value), type(real[name]), name)

	def test_discovery_of_the_mock_is_a_part_of_keycloaks(self):
		real = self._fixture("keycloak_discovery.json")
		self.assertLessEqual(set(_keycloak().discovery()), set(real))
		self.assertEqual(
			urlparse(_keycloak().jwks_uri).path.partition("/protocol/")[2], "openid-connect/certs"
		)
		self.assertTrue(real["jwks_uri"].endswith("/protocol/openid-connect/certs"))
		self.assertIn("S256", real["code_challenge_methods_supported"])


class TestCallback(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		frappe.get_doc(
			{
				"doctype": "Social Login Key",
				"provider_name": PROVIDER_KEY,
				"enable_social_login": 1,
				"client_id": CLIENT_ID,
				"client_secret": "synthetic-test-secret",
				"base_url": "https://untrusted.example.org",
				"authorize_url": "/api/method/frappe_sso_guard.api.callback.start",
				"access_token_url": UNTRUSTED_TOKEN_URL,
				"redirect_url": "/api/method/frappe_sso_guard.api.callback.handle_callback",
				"auth_url_data": json.dumps({"scope": "openid email profile"}),
				"sign_ups": "Allow",
			}
		).insert(ignore_permissions=True)
		frappe.db.set_single_value("SSO Identity Settings", "social_login_key", PROVIDER_KEY)
		frappe.db.set_single_value("SSO Identity Settings", "admin_notification_emails", "")

		# The callback commits because Frappe rolls back a GET request; here the test must roll back.
		commit = patch.object(frappe.db, "commit")
		commit.start()
		self.addCleanup(commit.stop)
		sendmail = patch.object(frappe, "sendmail")
		self.sendmail = sendmail.start()
		self.addCleanup(sendmail.stop)
		# Error Log is MyISAM: its rows outlive the rollback.
		log_error = patch.object(frappe, "log_error")
		log_error.start()
		self.addCleanup(log_error.stop)
		frappe.set_user("Guest")

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.flags.oidc_session_authorized = False
		idp.JWKS_CACHE.clear()
		frappe.db.rollback()

	def _use(self, provider: MockIdentityProvider, idp_type: str, issuer: str | None = None):
		"""Points the site at the mock provider for the rest of this test."""
		self.provider = provider
		frappe.db.set_single_value("SSO Identity Settings", "idp_type", idp_type)
		frappe.cache.delete_value(f"oidc_discovery_{provider.issuer}")
		for patcher in (
			patch.dict(frappe.conf, {"sso_issuer": issuer or provider.issuer}),
			patch.object(idp.requests, "get", provider.get),
			patch.object(idp.requests, "post", provider.post),
			patch.object(jwt.PyJWKClient, "fetch_data", lambda client: provider.jwks()),
		):
			patcher.start()
			self.addCleanup(patcher.stop)

	def _start(self) -> tuple[str, str]:
		"""Clicks the login button: returns the state and the cookie the browser received."""
		state = create_oauth_state("/after-sign-in")
		set_request(method="GET", path="/api/method/frappe_sso_guard.api.callback.start")
		frappe.local.cookie_manager = CookieManager()
		frappe.local.response = frappe._dict()
		start(state=state)
		location = urlparse(frappe.local.response["location"])
		self.authorize_url = f"{location.scheme}://{location.netloc}{location.path}"
		self.provider.authorize_params = {k: v[0] for k, v in parse_qs(location.query).items()}
		return state, frappe.local.cookie_manager.cookies[f"{FLOW_COOKIE_PREFIX}{state}"]["value"]

	def _callback(
		self,
		state: str,
		cookie: str | None,
		code: str | None = "code",
		error: str | None = None,
		real_session: bool = False,
	):
		headers = {"Cookie": f"{FLOW_COOKIE_PREFIX}{state}={cookie}"} if cookie else {}
		set_request(
			method="GET",
			path="/api/method/frappe_sso_guard.api.callback.handle_callback",
			headers=headers,
		)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.response = frappe._dict()
		frappe.local.message = None
		self.login_manager = LoginManager() if real_session else MagicMock()
		frappe.local.login_manager = self.login_manager
		handle_callback(code=code, state=state, error=error)

	def _sign_in(self):
		state, cookie = self._start()
		self._callback(state, cookie)

	def _assert_signed_in(self, user: str):
		self.login_manager.login_as.assert_called_once_with(user, session_end=ANY)
		self.assertTrue(frappe.flags.oidc_session_authorized)
		self.assertEqual(frappe.local.response["location"], "/after-sign-in")

	def _assert_refused(self, status: int = 403):
		self.login_manager.login_as.assert_not_called()
		self.assertFalse(frappe.flags.oidc_session_authorized)
		self.assertEqual(frappe.local.response["http_status_code"], status)

	def _bound_user(self, immutable_id: str = "kc-subject-1", email: str = "sso.person@example.org"):
		frappe.set_user("Administrator")
		user = frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "Synthetic",
				"send_welcome_email": 0,
				"social_logins": [{"provider": PROVIDER_KEY, "userid": immutable_id}] if immutable_id else [],
			}
		).insert(ignore_permissions=True)
		frappe.set_user("Guest")
		return user

	def _logged(self, event_type: str, **filters) -> bool:
		return bool(frappe.db.exists("SSO Identity Assignment Log", {"event_type": event_type, **filters}))

	# Team membership

	def _with_team_handler(self, handler, enabled=1):
		frappe.db.set_single_value("SSO Identity Settings", "enable_team_membership", enabled)
		frappe.db.set_single_value("SSO Identity Settings", "groups_claim", "groups")
		patcher = patch.object(team_membership, "_get_handlers", return_value=[handler])
		patcher.start()
		self.addCleanup(patcher.stop)
		return handler

	def test_groups_are_not_read_with_the_setting_off(self):
		handler = self._with_team_handler(MagicMock(return_value=[]), enabled=0)
		self._use(_keycloak(groups=["/a"]), "Keycloak")
		self._bound_user()
		self._sign_in()
		self._assert_signed_in(SSO_USER)
		handler.assert_not_called()

	def test_teams_are_set_before_the_session_opens(self):
		def handler(user, groups):
			self.login_manager.login_as.assert_not_called()
			return [{"team": "Team A", "group": groups[0], "action": "Added"}]

		self._with_team_handler(handler)
		self._use(_keycloak(groups=["/a"]), "Keycloak")
		self._bound_user()
		self._sign_in()
		self._assert_signed_in(SSO_USER)
		self.assertTrue(self._logged("Team Added", user=SSO_USER, idp_identifier="kc-subject-1"))

	def test_a_new_person_gets_their_teams_at_their_first_sign_in(self):
		handler = self._with_team_handler(MagicMock(return_value=[]))
		self._use(_keycloak(groups=["/a"]), "Keycloak")
		self._sign_in()
		self._assert_signed_in(SSO_USER)
		handler.assert_called_once_with(SSO_USER, ["/a"])

	def test_an_empty_list_of_groups_signs_in_and_clears_the_teams(self):
		handler = self._with_team_handler(MagicMock(return_value=[]))
		self._use(_keycloak(groups=[]), "Keycloak")
		self._bound_user()
		self._sign_in()
		self._assert_signed_in(SSO_USER)
		handler.assert_called_once_with(SSO_USER, [])

	def test_a_token_without_the_claim_means_no_groups(self):
		handler = self._with_team_handler(MagicMock(return_value=[]))
		self._use(_keycloak(), "Keycloak")
		self._bound_user()
		self._sign_in()
		self._assert_signed_in(SSO_USER)
		handler.assert_called_once_with(SSO_USER, [])

	def test_an_entra_token_over_its_limit_of_groups_is_refused(self):
		self._with_team_handler(MagicMock(return_value=[]))
		self._use(_entra(_claim_names={"groups": "src1"}), "Entra ID")
		self._sign_in()
		self._assert_refused()
		# Refused before anything is written.
		self.assertFalse(frappe.db.exists("User", SSO_USER))

	def test_teams_that_cannot_be_set_refuse_the_sign_in(self):
		self._with_team_handler(MagicMock(side_effect=frappe.ValidationError("no")))
		self._use(_keycloak(groups=["/a"]), "Keycloak")
		self._bound_user()
		self._sign_in()
		self._assert_refused()
		self.assertTrue(self._logged("Session Refused", user=SSO_USER))

	# Both identity providers, through the same code

	def _sign_in_with_mfa_required(self, provider, **conf):
		self._use(provider, "Keycloak")
		self._bound_user()
		with patch.dict(frappe.conf, conf):
			self._sign_in()

	def test_token_without_the_required_mfa_is_refused(self):
		self._sign_in_with_mfa_required(_keycloak(acr="1"), sso_mfa_values=["2", "gold"])
		self._assert_refused()
		self.assertTrue(self._logged("Session Refused", idp_identifier="kc-subject-1"))

	def test_token_with_no_mfa_claim_is_refused(self):
		self._sign_in_with_mfa_required(_keycloak(), sso_mfa_values="2")
		self._assert_refused()

	def test_token_with_the_required_acr_signs_in(self):
		self._sign_in_with_mfa_required(_keycloak(acr="2"), sso_mfa_values=["2", "gold"])
		self._assert_signed_in(SSO_USER)

	def test_token_listing_the_required_amr_signs_in(self):
		self._sign_in_with_mfa_required(
			_keycloak(amr=["pwd", "mfa"]), sso_mfa_claim="amr", sso_mfa_values=["mfa"]
		)
		self._assert_signed_in(SSO_USER)

	def test_keycloak_first_sign_in_creates_the_bound_user(self):
		self._use(_keycloak(), "Keycloak")
		self._sign_in()
		self._assert_signed_in("sso.person@example.org")
		self.assertEqual(
			frappe.db.get_value(
				"User Social Login", {"parent": "sso.person@example.org", "provider": PROVIDER_KEY}, "userid"
			),
			"kc-subject-1",
		)
		self.assertTrue(self._logged("User Created", user="sso.person@example.org"))
		self.assertTrue(self._logged("Login Success", user="sso.person@example.org"))

	def test_entra_identifies_by_oid_and_tid_not_sub(self):
		self._use(_entra(), "Entra ID")
		self._sign_in()
		self._assert_signed_in("sso.person@example.org")
		self.assertEqual(
			frappe.db.get_value(
				"User Social Login", {"parent": "sso.person@example.org", "provider": PROVIDER_KEY}, "userid"
			),
			"object-1:tenant-1",
		)

	def test_keys_come_from_discovery_on_both_providers(self):
		for provider, idp_type in ((_keycloak(), "Keycloak"), (_entra(), "Entra ID")):
			self._use(provider, idp_type)
			self._start()
			self.assertEqual(self.authorize_url, provider.discovery()["authorization_endpoint"])
			config = idp.get_openid_configuration(provider.issuer)
			self.assertEqual(config["jwks_uri"], provider.jwks_uri)

	def test_new_user_holds_no_role_and_no_desk_access(self):
		self._use(_keycloak(), "Keycloak")
		self._sign_in()
		user = frappe.get_doc("User", "sso.person@example.org")
		self.assertEqual(user.user_type, "Website User")
		self.assertFalse([row for row in user.roles if row.role not in ("All", "Guest")])

	def test_start_sends_nonce_and_pkce_to_the_pinned_provider(self):
		self._use(_keycloak(), "Keycloak")
		self._start()
		params = self.provider.authorize_params
		self.assertEqual(self.authorize_url, f"{self.provider.issuer}/authorize")
		self.assertEqual(params["code_challenge_method"], "S256")
		self.assertTrue(params["code_challenge"] and params["nonce"])
		self.assertEqual(params["client_id"], CLIENT_ID)

	def test_token_request_ignores_the_editable_social_login_key(self):
		self._use(_keycloak(), "Keycloak")
		self._sign_in()
		self.assertEqual(self.provider.token_urls, [f"{self.provider.issuer}/token"])
		self.assertNotIn(UNTRUSTED_TOKEN_URL, self.provider.token_urls)

	# State, browser binding, PKCE

	def test_start_refuses_an_unknown_state(self):
		self._use(_keycloak(), "Keycloak")
		set_request(method="GET", path="/")
		frappe.local.cookie_manager = CookieManager()
		frappe.local.response = frappe._dict()
		start(state="not-a-known-state")
		self.assertEqual(frappe.local.response["http_status_code"], 403)
		self.assertNotIn("location", frappe.local.response)

	def test_callback_refuses_a_forged_state(self):
		self._use(_keycloak(), "Keycloak")
		self._start()
		self._callback("forged-state", "forged-cookie")
		self._assert_refused()

	def test_callback_refuses_another_browser(self):
		self._use(_keycloak(), "Keycloak")
		state, _cookie = self._start()
		self._callback(state, None)
		self._assert_refused()
		self._callback(state, "cookie-of-another-browser")
		self._assert_refused()

	def test_another_browser_cannot_cancel_a_real_sign_in(self):
		self._use(_keycloak(), "Keycloak")
		state, cookie = self._start()
		self._callback(state, "cookie-of-another-browser")
		self._callback(state, cookie)
		self._assert_signed_in("sso.person@example.org")

	def test_a_state_works_only_once(self):
		self._use(_keycloak(), "Keycloak")
		state, cookie = self._start()
		self._callback(state, cookie)
		self._assert_signed_in("sso.person@example.org")
		frappe.flags.oidc_session_authorized = False
		self._callback(state, cookie)
		self._assert_refused()

	def test_wrong_pkce_verifier_is_refused(self):
		self._use(_keycloak(), "Keycloak")
		state, cookie = self._start()
		self.provider.authorize_params["code_challenge"] = "challenge-of-another-sign-in"
		self._callback(state, cookie)
		self._assert_refused(502)

	# The ID token

	def _assert_token_refused(self):
		self._sign_in()
		self._assert_refused()
		self.assertFalse(frappe.db.exists("User", "sso.person@example.org"))
		self.assertTrue(self._logged("Session Refused"))

	def test_wrong_nonce_is_refused(self):
		self._use(_keycloak(nonce="nonce-of-another-sign-in"), "Keycloak")
		self._assert_token_refused()

	def test_missing_nonce_is_refused(self):
		provider = _keycloak()
		provider.claim_overrides = {"nonce": None}
		self._use(provider, "Keycloak")
		self._assert_token_refused()

	def test_wrong_issuer_is_refused(self):
		provider = _keycloak()
		provider.claim_overrides = {"iss": "https://other-provider.example.org"}
		self._use(provider, "Keycloak")
		self._assert_token_refused()

	def test_wrong_audience_is_refused(self):
		provider = _keycloak()
		provider.claim_overrides = {"aud": "another-client"}
		self._use(provider, "Keycloak")
		self._assert_token_refused()

	def test_expired_token_is_refused(self):
		provider = _keycloak()
		provider.claim_overrides = {"exp": int(time.time()) - 3600}
		self._use(provider, "Keycloak")
		self._assert_token_refused()

	def test_token_signed_by_another_key_is_refused(self):
		provider = _keycloak()
		provider.sign_with = dict(key=_pem(OTHER_KEY), algorithm="RS256")
		self._use(provider, "Keycloak")
		self._assert_token_refused()

	def test_symmetric_algorithm_is_refused(self):
		provider = _keycloak()
		provider.sign_with = dict(key="synthetic-shared-secret-long-enough-for-hs256", algorithm="HS256")
		self._use(provider, "Keycloak")
		self._assert_token_refused()

	def test_unsigned_token_is_refused(self):
		provider = _keycloak()
		provider.sign_with = dict(key=None, algorithm="none")
		self._use(provider, "Keycloak")
		self._assert_token_refused()

	def test_entra_token_without_tenant_is_refused(self):
		self._use(_entra(tid=None), "Entra ID")
		self._assert_token_refused()

	# Pinning

	def test_a_site_without_a_pinned_issuer_refuses(self):
		provider = _keycloak()
		self._use(provider, "Keycloak")
		state = create_oauth_state("/after-sign-in")
		with patch.dict(frappe.conf, {"sso_issuer": None}):
			set_request(method="GET", path="/")
			frappe.local.cookie_manager = CookieManager()
			frappe.local.response = frappe._dict()
			start(state=state)
		self.assertEqual(frappe.local.response["http_status_code"], 502)
		self.assertNotIn("location", frappe.local.response)

	def test_discovery_naming_another_issuer_is_refused(self):
		provider = _keycloak()
		self._use(provider, "Keycloak", issuer="https://pinned.example.org/realms/test")
		state = create_oauth_state("/after-sign-in")
		set_request(method="GET", path="/")
		frappe.local.cookie_manager = CookieManager()
		frappe.local.response = frappe._dict()
		start(state=state)
		self.assertEqual(frappe.local.response["http_status_code"], 502)

	# Matching the user

	def test_known_identifier_signs_in_whatever_the_email_says(self):
		self._use(_keycloak(email="new.address@example.org"), "Keycloak")
		self._bound_user()
		self._sign_in()
		self._assert_signed_in("sso.person@example.org")
		self.assertFalse(frappe.db.exists("User", "new.address@example.org"))
		self.assertTrue(self._logged("Email Changed", user="sso.person@example.org", status="Warning"))

	def test_changed_email_held_by_another_user_is_refused(self):
		self._use(_keycloak(email="taken@example.org"), "Keycloak")
		self._bound_user()
		self._bound_user(immutable_id="kc-subject-2", email="taken@example.org")
		self._sign_in()
		self._assert_refused()

	def test_verified_email_binds_an_unbound_account(self):
		self._use(_keycloak(), "Keycloak")
		self._bound_user(immutable_id=None)
		self._sign_in()
		self._assert_signed_in("sso.person@example.org")
		self.assertTrue(self._logged("User Bound", user="sso.person@example.org"))

	def test_unverified_email_cannot_take_over_an_account(self):
		self._use(_keycloak(email_verified=False), "Keycloak")
		self._bound_user(immutable_id=None)
		self._sign_in()
		self._assert_refused()
		self.assertFalse(
			frappe.db.exists(
				"User Social Login", {"parent": "sso.person@example.org", "provider": PROVIDER_KEY}
			)
		)

	def test_entra_email_without_domain_verification_cannot_take_over_an_account(self):
		self._use(_entra(xms_edov=None), "Entra ID")
		self._bound_user(immutable_id=None)
		self._sign_in()
		self._assert_refused()

	def test_email_of_an_account_bound_to_another_identity_is_refused(self):
		self._use(_keycloak(sub="kc-subject-2"), "Keycloak")
		self._bound_user(immutable_id="kc-subject-1")
		self._sign_in()
		self._assert_refused()
		self.assertTrue(self._logged("Session Refused", user="sso.person@example.org"))

	def test_administrator_cannot_be_taken_over_by_email(self):
		administrator_email = frappe.db.get_value("User", "Administrator", "email")
		self._use(_keycloak(email=administrator_email), "Keycloak")
		self._sign_in()
		self._assert_refused()
		self.assertFalse(frappe.db.exists("User Social Login", {"parent": "Administrator"}))

	def test_disabled_user_is_refused(self):
		self._use(_keycloak(), "Keycloak")
		self._bound_user()
		frappe.db.set_value("User", "sso.person@example.org", "enabled", 0)
		self._sign_in()
		self._assert_refused()

	def test_sign_ups_denied_creates_no_user(self):
		self._use(_keycloak(), "Keycloak")
		frappe.db.set_value("Social Login Key", PROVIDER_KEY, "sign_ups", "Deny")
		self._sign_in()
		self._assert_refused()
		self.assertFalse(frappe.db.exists("User", "sso.person@example.org"))

	def test_email_claim_is_matched_in_lowercase(self):
		self._use(_keycloak(email="SSO.Person@Example.org"), "Keycloak")
		self._bound_user(immutable_id=None)
		self._sign_in()
		self._assert_signed_in("sso.person@example.org")

	def test_refusals_of_an_account_notify_the_administrators(self):
		self._use(_keycloak(sub="kc-subject-2"), "Keycloak")
		self._bound_user()
		frappe.db.set_single_value("SSO Identity Settings", "admin_notification_emails", "admin@example.org")
		self._sign_in()
		self.sendmail.assert_called_once()
		self.assertEqual(self.sendmail.call_args.kwargs["recipients"], ["admin@example.org"])

	# What reaches the page

	def test_error_parameter_never_reaches_the_page(self):
		self._use(_keycloak(), "Keycloak")
		state, cookie = self._start()
		self._callback(state, cookie, code=None, error=PAYLOAD)
		self._assert_refused()
		self.assertNotIn("onerror", frappe.local.message)

	def test_forged_callback_with_error_shows_fixed_text_and_writes_nothing(self):
		self._use(_keycloak(), "Keycloak")
		before = frappe.db.count("SSO Identity Assignment Log")
		self._callback("forged-state", None, error=PAYLOAD)
		self._assert_refused()
		self.assertNotIn("onerror", frappe.local.message)
		self.assertEqual(frappe.db.count("SSO Identity Assignment Log"), before)

	def test_token_failure_shows_no_exception_text(self):
		provider = _keycloak()
		provider.claim_overrides = {"aud": PAYLOAD}
		self._use(provider, "Keycloak")
		self._sign_in()
		self._assert_refused()
		self.assertNotIn("onerror", frappe.local.message)
		self.assertNotIn("Audience", frappe.local.message)

	def test_identity_provider_outage_shows_no_exception_text(self):
		provider = _keycloak()
		self._use(provider, "Keycloak")
		state, cookie = self._start()
		with patch.object(
			idp.requests, "post", side_effect=requests.ConnectionError(f"{provider.issuer} is down")
		):
			self._callback(state, cookie)
		self._assert_refused(502)
		self.assertNotIn(provider.issuer, frappe.local.message)

	# The value given to Frappe

	def _set_session_max_hours(self, hours):
		"""Saves the value the way the settings page does, through the controller."""
		frappe.set_user("Administrator")
		settings = frappe.get_single("SSO Identity Settings")
		settings.session_max_hours = hours
		settings.save()
		frappe.set_user("Guest")

	def _assert_session_end_is_hours_ahead(self, hours: int):
		before = datetime.now(tz=UTC)
		self._sign_in()
		after = datetime.now(tz=UTC)
		session_end = datetime.fromisoformat(self.login_manager.login_as.call_args.kwargs["session_end"])
		self.assertEqual(session_end.utcoffset(), timedelta(0))
		self.assertLessEqual(before + timedelta(hours=hours), session_end)
		self.assertLessEqual(session_end, after + timedelta(hours=hours))

	def test_keycloak_login_as_receives_an_aware_end_the_configured_hours_ahead(self):
		self._use(_keycloak(), "Keycloak")
		self._set_session_max_hours(5)
		self._assert_session_end_is_hours_ahead(5)

	def test_entra_login_as_receives_an_aware_end_the_configured_hours_ahead(self):
		self._use(_entra(), "Entra ID")
		self._set_session_max_hours(5)
		self._assert_session_end_is_hours_ahead(5)

	def test_changing_the_setting_changes_the_next_sign_in(self):
		self._use(_keycloak(), "Keycloak")
		self._set_session_max_hours(5)
		self._assert_session_end_is_hours_ahead(5)
		self._set_session_max_hours(2)
		self._assert_session_end_is_hours_ahead(2)

	def test_a_site_without_a_stored_value_uses_twelve_hours(self):
		self.assertEqual(
			frappe.get_meta("SSO Identity Settings").get_field("session_max_hours").default, "12"
		)
		frappe.db.set_single_value("SSO Identity Settings", "session_max_hours", None)
		self.assertEqual(idp.get_sso_config()["session_max_hours"], 12)

	# Frappe's own LoginManager and Session, with the clock moved instead of waiting

	def _open_session(self, hours: int) -> tuple[str, datetime]:
		"""Signs in through the whole callback. Returns the session id and its end."""
		self._use(_keycloak(), "Keycloak")
		self._set_session_max_hours(hours)
		state, cookie = self._start()
		self._callback(state, cookie, real_session=True)
		self.assertEqual(frappe.session.user, SSO_USER)
		sid = frappe.session.sid
		# Outside the transaction the test rolls back.
		self.addCleanup(frappe.cache.hdel, "session", sid)
		self.addCleanup(delattr, frappe.local, "session_obj")
		return sid, datetime.fromisoformat(frappe.session.data.session_end)

	def _request_at(self, moment: datetime, sid: str) -> str:
		"""A request carrying the session's cookie, ending as Frappe ends one. Returns who it ran as.

		Only what Redis and the database hold carries over from earlier requests.
		"""
		with self.freeze_time(moment, is_utc=True):
			frappe.local.cache = {}
			set_request(method="GET", path="/", headers={"Cookie": f"sid={sid}"})
			frappe.local.cookie_manager = CookieManager()
			frappe.local.response = frappe._dict()
			frappe.local.login_manager = LoginManager()
			frappe.local.session_obj.update()
		return frappe.session.user

	def _session_row(self, sid: str) -> dict | None:
		sessions = frappe.qb.DocType("Sessions")
		rows = (
			frappe.qb.from_(sessions).select(sessions.sessiondata).where(sessions.sid == sid).run(pluck=True)
		)
		return frappe.parse_json(rows[0]) if rows else None

	def _assert_session_ended(self, sid: str):
		self.assertEqual(frappe.local.response.get("session_expired"), 1)
		self.assertIsNone(self._session_row(sid))
		self.assertIsNone(frappe.cache.hget("session", sid))

	def test_the_end_reaches_frappes_session_in_cache_and_database(self):
		sid, session_end = self._open_session(hours=3)
		stored = session_end.isoformat()
		self.assertEqual(frappe.cache.hget("session", sid).data.session_end, stored)
		self.assertEqual(self._session_row(sid).session_end, stored)

	def test_session_before_its_end_is_kept(self):
		sid, session_end = self._open_session(hours=1)
		self.assertEqual(self._request_at(session_end - timedelta(seconds=1), sid), SSO_USER)
		self.assertIsNotNone(self._session_row(sid))

	def test_session_past_its_end_is_refused(self):
		sid, session_end = self._open_session(hours=1)
		self.assertEqual(self._request_at(session_end + timedelta(seconds=1), sid), "Guest")
		self._assert_session_ended(sid)

	def test_activity_does_not_extend_the_end(self):
		sid, session_end = self._open_session(hours=1)
		first_update = self._session_row(sid).last_updated
		for minutes_left in (40, 20, 1):
			moment = session_end - timedelta(minutes=minutes_left)
			self.assertEqual(self._request_at(moment, sid), SSO_USER)

		# The activity counted: it moved the idle timeout, and only that.
		self.assertNotEqual(self._session_row(sid).last_updated, first_update)
		self.assertEqual(self._session_row(sid).session_end, session_end.isoformat())
		self.assertEqual(frappe.cache.hget("session", sid).data.session_end, session_end.isoformat())

		self.assertEqual(self._request_at(session_end + timedelta(seconds=1), sid), "Guest")
		self._assert_session_ended(sid)

	def test_changing_the_setting_leaves_an_open_session_as_it_is(self):
		sid, session_end = self._open_session(hours=5)
		self._set_session_max_hours(1)
		self.assertEqual(self._request_at(session_end - timedelta(hours=2), sid), SSO_USER)
		self.assertEqual(self._session_row(sid).session_end, session_end.isoformat())

	def test_idle_timeout_still_ends_a_session_before_its_end(self):
		idle = timedelta(seconds=get_expiry_in_seconds())
		hours = int(idle.total_seconds() / 3600) + 10
		limit = patch.dict(frappe.conf, {"sso_session_max_hours_limit": hours})
		limit.start()
		self.addCleanup(limit.stop)
		sid, session_end = self._open_session(hours=hours)
		moment = datetime.now(tz=UTC) + idle + timedelta(minutes=1)
		self.assertLess(moment, session_end)
		self.assertEqual(self._request_at(moment, sid), "Guest")
		self._assert_session_ended(sid)

	def test_session_from_the_database_is_refused_on_the_following_request(self):
		"""After a cache loss Frappe skips the check once, then the session is back in cache."""
		sid, session_end = self._open_session(hours=1)
		frappe.cache.hdel("session", sid)
		past_end = session_end + timedelta(seconds=1)
		self.assertEqual(self._request_at(past_end, sid), SSO_USER)
		self.assertEqual(self._request_at(past_end, sid), "Guest")
		self._assert_session_ended(sid)
