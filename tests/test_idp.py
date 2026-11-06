# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from frappe_sso_guard.services import idp
from tests.conftest import MockDoc

pytestmark = pytest.mark.unit

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


@pytest.fixture(scope="module")
def signing_key():
	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwk_client(mocker, signing_key):
	"""Serves the test key in place of the identity provider's JWKS endpoint."""
	client = MagicMock()
	client.get_signing_key_from_jwt.return_value = SimpleNamespace(key=signing_key.public_key())
	mocker.patch.object(idp, "get_jwk_client", return_value=client)
	return client


def make_claims(**overrides):
	now = int(time.time())
	claims = {
		"iss": ISSUER,
		"aud": AUDIENCE,
		"sub": "synthetic-subject",
		"iat": now,
		"exp": now + 300,
		"nonce": NONCE,
	}
	claims.update(overrides)
	return {key: value for key, value in claims.items() if value is not None}


def verify(token, nonce=NONCE):
	return idp.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE, nonce)


def test_get_sso_config_reads_the_site_config_and_settings(mock_frappe):
	mock_frappe.conf.update(force_sso=0, sso_issuer=ISSUER)
	mock_frappe.get_single.return_value = MockDoc(
		social_login_key="keycloak", session_max_hours=8, idp_type="Dex", enable_single_logout=1
	)

	config = idp.get_sso_config()

	assert config["force_sso"] == 0
	assert config["sso_issuer"] == ISSUER
	assert config["social_login_key"] == "keycloak"
	assert config["session_max_hours"] == 8
	assert config["idp_type"] == "Dex"
	assert config["enable_single_logout"] is True


def test_get_sso_config_defaults(mock_frappe):
	config = idp.get_sso_config()

	assert config["force_sso"] == 1
	assert config["session_max_hours"] == 12
	assert config["idp_type"] == "Keycloak"
	assert config["enable_single_logout"] is False


def test_get_sso_config_falls_back_to_the_site_config_key(mock_frappe):
	mock_frappe.conf["sso_provider_key"] = "from-site-config"
	assert idp.get_sso_config()["social_login_key"] == "from-site-config"


@pytest.mark.security
def test_sign_in_is_refused_without_a_pinned_issuer(mock_frappe):
	mock_frappe.get_single.return_value = MockDoc(social_login_key="keycloak")
	with pytest.raises(idp.SSONotConfiguredError, match="sso_issuer"):
		idp.get_sign_in_config()


@pytest.mark.security
def test_sign_in_is_refused_without_a_social_login_key(mock_frappe):
	mock_frappe.conf["sso_issuer"] = ISSUER
	with pytest.raises(idp.SSONotConfiguredError, match="Social Login Key"):
		idp.get_sign_in_config()


def test_sign_in_config_with_both_settings(mock_frappe):
	mock_frappe.conf["sso_issuer"] = ISSUER
	mock_frappe.get_single.return_value = MockDoc(social_login_key="keycloak")
	assert idp.get_sign_in_config()["sso_issuer"] == ISSUER


def test_discovery_is_fetched_and_cached(mock_frappe, mocker):
	get = mocker.patch.object(idp.requests, "get")
	get.return_value.json.return_value = DISCOVERY

	assert idp.get_openid_configuration(ISSUER) == DISCOVERY

	get.assert_called_once_with(f"{ISSUER}{idp.DISCOVERY_PATH}", timeout=idp.HTTP_TIMEOUT_SECONDS)
	mock_frappe.cache.set_value.assert_called_once()


def test_discovery_from_the_cache_makes_no_request(mock_frappe, mocker):
	get = mocker.patch.object(idp.requests, "get")
	mock_frappe.cache.get_value.return_value = DISCOVERY

	assert idp.get_openid_configuration(ISSUER) == DISCOVERY
	get.assert_not_called()


@pytest.mark.security
def test_discovery_naming_another_issuer_is_refused_and_not_cached(mock_frappe, mocker):
	get = mocker.patch.object(idp.requests, "get")
	get.return_value.json.return_value = {**DISCOVERY, "issuer": "https://other.example.com"}

	with pytest.raises(ValueError, match="another issuer"):
		idp.get_openid_configuration(ISSUER)
	mock_frappe.cache.set_value.assert_not_called()


@pytest.mark.parametrize("field", ["authorization_endpoint", "token_endpoint", "jwks_uri"])
def test_discovery_lacking_an_endpoint_is_refused(mocker, field):
	get = mocker.patch.object(idp.requests, "get")
	get.return_value.json.return_value = {**DISCOVERY, field: None}

	with pytest.raises(ValueError, match="lacks an endpoint"):
		idp.get_openid_configuration(ISSUER)


def test_jwk_client_is_built_once_per_uri(mocker):
	mocker.patch.dict(idp.JWKS_CACHE, clear=True)
	client_class = mocker.patch.object(idp, "PyJWKClient")

	assert idp.get_jwk_client(JWKS_URI) is idp.get_jwk_client(JWKS_URI)
	client_class.assert_called_once()


def test_code_challenge_matches_the_rfc_7636_example():
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	assert idp.make_code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_exchange_code_sends_the_verifier_and_a_timeout(mocker):
	post = mocker.patch.object(idp.requests, "post")
	post.return_value.json.return_value = {"id_token": "token"}

	tokens = idp.exchange_code(
		DISCOVERY["token_endpoint"], "code", "https://site/cb", "id", "secret", "verifier"
	)

	assert tokens == {"id_token": "token"}
	post.return_value.raise_for_status.assert_called_once()
	assert post.call_args.kwargs["data"]["code_verifier"] == "verifier"
	assert post.call_args.kwargs["data"]["grant_type"] == "authorization_code"
	assert post.call_args.kwargs["timeout"] == idp.HTTP_TIMEOUT_SECONDS


@pytest.mark.security
def test_valid_id_token_returns_its_claims(signing_key, jwk_client):
	token = jwt.encode(make_claims(), signing_key, algorithm="RS256")
	assert verify(token)["sub"] == "synthetic-subject"


@pytest.mark.security
@pytest.mark.parametrize(
	"overrides, error",
	[
		({"iss": "https://other.example.com"}, jwt.InvalidIssuerError),
		({"aud": "another-client"}, jwt.InvalidAudienceError),
		({"exp": int(time.time()) - 3600}, jwt.ExpiredSignatureError),
		({"sub": None}, jwt.MissingRequiredClaimError),
		({"iat": None}, jwt.MissingRequiredClaimError),
		({"exp": None}, jwt.MissingRequiredClaimError),
	],
)
def test_id_token_with_bad_claims_is_refused(signing_key, jwk_client, overrides, error):
	token = jwt.encode(make_claims(**overrides), signing_key, algorithm="RS256")
	with pytest.raises(error):
		verify(token)


@pytest.mark.security
@pytest.mark.parametrize("nonce", ["another-nonce", None])
def test_id_token_with_another_nonce_is_refused(signing_key, jwk_client, nonce):
	token = jwt.encode(make_claims(nonce=nonce), signing_key, algorithm="RS256")
	with pytest.raises(ValueError, match="nonce"):
		verify(token)


@pytest.mark.security
def test_id_token_signed_by_another_key_is_refused(jwk_client):
	other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	token = jwt.encode(make_claims(), other_key, algorithm="RS256")
	with pytest.raises(jwt.InvalidSignatureError):
		verify(token)


@pytest.mark.security
def test_id_token_with_a_symmetric_algorithm_is_refused(jwk_client):
	token = jwt.encode(make_claims(), "synthetic-shared-secret-of-sufficient-length", algorithm="HS256")
	with pytest.raises(jwt.InvalidAlgorithmError):
		verify(token)
