# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import frappe
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from frappe.tests import UnitTestCase

from frappe_sso_guard.services import idp

ISSUER = "https://idp.example.com/realms/test"
AUDIENCE = "frappe-client"
NONCE = "synthetic-nonce"
JWKS_URI = f"{ISSUER}/certs"
DISCOVERY = {
	"issuer": ISSUER,
	"authorization_endpoint": f"{ISSUER}/auth",
	"token_endpoint": f"{ISSUER}/token",
	"jwks_uri": JWKS_URI,
}


def _settings(**fields):
	return patch.object(frappe, "get_single", return_value=frappe._dict(fields))


class TestSSOConfig(UnitTestCase):
	@patch.dict(frappe.conf, {"force_sso": 0, "sso_issuer": ISSUER}, clear=True)
	def test_reads_the_site_config_and_settings(self):
		settings = {
			"social_login_key": "keycloak",
			"session_max_hours": 8,
			"idp_type": "Dex",
			"enable_single_logout": 1,
		}
		with _settings(**settings):
			config = idp.get_sso_config()

		self.assertEqual(config["force_sso"], 0)
		self.assertEqual(config["sso_issuer"], ISSUER)
		self.assertEqual(config["social_login_key"], "keycloak")
		self.assertEqual(config["session_max_hours"], 8)
		self.assertEqual(config["idp_type"], "Dex")
		self.assertIs(config["enable_single_logout"], True)

	@patch.dict(frappe.conf, clear=True)
	def test_defaults(self):
		with _settings():
			config = idp.get_sso_config()

		self.assertEqual(config["force_sso"], 1)
		self.assertEqual(config["session_max_hours"], 12)
		self.assertEqual(config["idp_type"], "Keycloak")
		self.assertIs(config["enable_single_logout"], False)

	@patch.dict(frappe.conf, {"sso_provider_key": "from-site-config"}, clear=True)
	def test_falls_back_to_the_site_config_key(self):
		with _settings():
			self.assertEqual(idp.get_sso_config()["social_login_key"], "from-site-config")

	@patch.dict(frappe.conf, clear=True)
	def test_sign_in_is_refused_without_a_pinned_issuer(self):
		with (
			_settings(social_login_key="keycloak"),
			self.assertRaisesRegex(idp.SSONotConfiguredError, "sso_issuer"),
		):
			idp.get_sign_in_config()

	@patch.dict(frappe.conf, {"sso_issuer": ISSUER}, clear=True)
	def test_sign_in_is_refused_without_a_social_login_key(self):
		with _settings(), self.assertRaisesRegex(idp.SSONotConfiguredError, "Social Login Key"):
			idp.get_sign_in_config()

	@patch.dict(frappe.conf, {"sso_issuer": ISSUER}, clear=True)
	def test_sign_in_config_with_both_settings(self):
		with _settings(social_login_key="keycloak"):
			self.assertEqual(idp.get_sign_in_config()["sso_issuer"], ISSUER)


class TestDiscovery(UnitTestCase):
	def setUp(self):
		cache_patch = patch.object(frappe, "cache", MagicMock())
		self.cache = cache_patch.start()
		self.addCleanup(cache_patch.stop)
		self.cache.get_value.return_value = None

		get_patch = patch.object(idp.requests, "get")
		self.get = get_patch.start()
		self.addCleanup(get_patch.stop)

	def test_is_fetched_and_cached(self):
		self.get.return_value.json.return_value = DISCOVERY

		self.assertEqual(idp.get_openid_configuration(ISSUER), DISCOVERY)

		self.get.assert_called_once_with(f"{ISSUER}{idp.DISCOVERY_PATH}", timeout=idp.HTTP_TIMEOUT_SECONDS)
		self.cache.set_value.assert_called_once()

	def test_from_the_cache_makes_no_request(self):
		self.cache.get_value.return_value = DISCOVERY

		self.assertEqual(idp.get_openid_configuration(ISSUER), DISCOVERY)
		self.get.assert_not_called()

	def test_naming_another_issuer_is_refused_and_not_cached(self):
		self.get.return_value.json.return_value = {**DISCOVERY, "issuer": "https://other.example.com"}

		with self.assertRaisesRegex(ValueError, "another issuer"):
			idp.get_openid_configuration(ISSUER)
		self.cache.set_value.assert_not_called()

	def test_lacking_an_endpoint_is_refused(self):
		for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
			self.get.return_value.json.return_value = {**DISCOVERY, field: None}
			with self.subTest(field=field), self.assertRaisesRegex(ValueError, "lacks an endpoint"):
				idp.get_openid_configuration(ISSUER)


class TestTokenExchange(UnitTestCase):
	@patch.dict(idp.JWKS_CACHE, clear=True)
	def test_jwk_client_is_built_once_per_uri(self):
		with patch.object(idp, "PyJWKClient") as client_class:
			self.assertIs(idp.get_jwk_client(JWKS_URI), idp.get_jwk_client(JWKS_URI))
		client_class.assert_called_once()

	def test_code_challenge_matches_the_rfc_7636_example(self):
		verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		self.assertEqual(idp.make_code_challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

	def test_exchange_code_sends_the_verifier_and_a_timeout(self):
		with patch.object(idp.requests, "post") as post:
			post.return_value.json.return_value = {"id_token": "token"}
			tokens = idp.exchange_code(
				DISCOVERY["token_endpoint"], "code", "https://site/cb", "id", "secret", "verifier"
			)

		self.assertEqual(tokens, {"id_token": "token"})
		post.return_value.raise_for_status.assert_called_once()
		self.assertEqual(post.call_args.kwargs["data"]["code_verifier"], "verifier")
		self.assertEqual(post.call_args.kwargs["data"]["grant_type"], "authorization_code")
		self.assertEqual(post.call_args.kwargs["timeout"], idp.HTTP_TIMEOUT_SECONDS)


class TestVerifyIdToken(UnitTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	def setUp(self):
		# Serves the test key in place of the identity provider's JWKS endpoint.
		client = MagicMock()
		client.get_signing_key_from_jwt.return_value = SimpleNamespace(key=self.signing_key.public_key())
		client_patch = patch.object(idp, "get_jwk_client", return_value=client)
		client_patch.start()
		self.addCleanup(client_patch.stop)

	def _token(self, key=None, algorithm="RS256", **overrides):
		now = int(time.time())
		claims = {
			"iss": ISSUER,
			"aud": AUDIENCE,
			"sub": "synthetic-subject",
			"iat": now,
			"exp": now + 300,
			"nonce": NONCE,
			**overrides,
		}
		claims = {name: value for name, value in claims.items() if value is not None}
		return jwt.encode(claims, key or self.signing_key, algorithm=algorithm)

	def _verify(self, token):
		return idp.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE, NONCE)

	def test_valid_token_returns_its_claims(self):
		self.assertEqual(self._verify(self._token())["sub"], "synthetic-subject")

	def test_bad_claims_are_refused(self):
		cases = (
			({"iss": "https://other.example.com"}, jwt.InvalidIssuerError),
			({"aud": "another-client"}, jwt.InvalidAudienceError),
			({"exp": int(time.time()) - 3600}, jwt.ExpiredSignatureError),
			({"sub": None}, jwt.MissingRequiredClaimError),
			({"iat": None}, jwt.MissingRequiredClaimError),
			({"exp": None}, jwt.MissingRequiredClaimError),
		)
		for overrides, error in cases:
			with self.subTest(overrides=overrides), self.assertRaises(error):
				self._verify(self._token(**overrides))

	def test_another_nonce_is_refused(self):
		for nonce in ("another-nonce", None):
			with self.subTest(nonce=nonce), self.assertRaisesRegex(ValueError, "nonce"):
				self._verify(self._token(nonce=nonce))

	def test_another_signing_key_is_refused(self):
		other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		with self.assertRaises(jwt.InvalidSignatureError):
			self._verify(self._token(key=other_key))

	def test_a_symmetric_algorithm_is_refused(self):
		token = self._token(key="synthetic-shared-secret-of-sufficient-length", algorithm="HS256")
		with self.assertRaises(jwt.InvalidAlgorithmError):
			self._verify(token)
