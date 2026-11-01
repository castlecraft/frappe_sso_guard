import unittest
from unittest.mock import MagicMock, patch

import frappe
import requests

from frappe_sso_guard.api.callback import handle_callback


class TestEndToEndOIDC(unittest.TestCase):
	def setUp(self):
		self.issuer = "http://dex.localhost:5556/dex"
		frappe.flags.oidc_session_authorized = False

	def tearDown(self):
		frappe.flags.oidc_session_authorized = False

	def test_dex_discovery_available(self):
		try:
			resp = requests.get(f"{self.issuer}/.well-known/openid-configuration", timeout=5)
			self.assertEqual(resp.status_code, 200)
		except requests.RequestException:
			self.skipTest("Dex OIDC server is not running")

	@patch("frappe_sso_guard.api.callback.consume_oauth_state")
	@patch("frappe_sso_guard.api.callback.requests.post")
	@patch("jwt.decode")
	@patch("frappe_sso_guard.api.callback.PyJWKClient")
	def test_e2e_successful_callback_exchange(
		self,
		mock_jwk_client,
		mock_jwt_decode,
		mock_post_token,
		mock_consume_state,
	):
		mock_consume_state.return_value = "/app"

		mock_token_resp = MagicMock()
		mock_token_resp.json.return_value = {
			"id_token": "valid.id.token",
			"access_token": "valid.access.token",
		}
		mock_post_token.return_value = mock_token_resp

		mock_jwt_decode.return_value = {
			"sub": "08a5da84-ac59-4a7c-9203-82aa34794ba9",
			"email": "caseworker@example.org",
			"name": "Caseworker",
		}

		mock_signing_key = MagicMock()
		mock_signing_key.key = "fake_key"
		mock_jwk_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

		mock_lm = MagicMock()
		frappe.local.login_manager = mock_lm
		try:
			handle_callback(code="auth-code-xyz", state="valid-state-123")
			self.assertTrue(frappe.flags.oidc_session_authorized)
			mock_lm.login_as.assert_called_once()
		finally:
			if hasattr(frappe.local, "login_manager"):
				delattr(frappe.local, "login_manager")
