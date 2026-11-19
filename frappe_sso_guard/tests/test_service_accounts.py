# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

import time
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import frappe
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from frappe.core.doctype.user.user import generate_keys
from frappe.tests import IntegrationTestCase
from frappe.tests.test_api import make_request
from frappe.utils import get_test_client

from frappe_sso_guard.guard import service_accounts

ISSUER = "https://keycloak.example.org/realms/service-account-test"
AUDIENCE = "frappe-api"
WHOAMI = "/api/method/frappe.auth.get_logged_user"


class TestServiceAccounts(IntegrationTestCase):
	"""Use the real request pipeline, database mappings, and signed JWTs with a local test signing key."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	def setUp(self):
		frappe.set_user("Administrator")
		self.subject = str(uuid4())
		self.client_id = f"service-{self.subject}"
		self.email = f"{self.client_id}@example.org"
		self.client = get_test_client(use_cookies=False)
		# get_site_config also runs on the thread serving each HTTP request.
		read_config = frappe.get_site_config
		self.config = {"sso_issuer": ISSUER, "sso_service_token_audience": AUDIENCE}
		self.enterContext(patch.dict(frappe.conf, self.config))
		self.enterContext(
			patch.object(
				frappe, "get_site_config", lambda **kw: frappe._dict({**read_config(**kw), **self.config})
			)
		)
		self.enterContext(
			patch.object(
				service_accounts, "get_openid_configuration", return_value={"jwks_uri": ISSUER + "/certs"}
			)
		)
		jwks = self.enterContext(patch.object(service_accounts, "get_jwk_client")).return_value
		jwks.get_signing_key_from_jwt.return_value = SimpleNamespace(key=self.key.public_key())
		self.user = frappe.get_doc(
			{
				"doctype": "User",
				"email": self.email,
				"first_name": "Integration",
				"user_type": "Website User",
				"send_welcome_email": 0,
			}
		).insert()
		self.mapping = frappe.get_doc(
			{
				"doctype": "SSO Service Account",
				"client_id": self.client_id,
				"subject": self.subject,
				"user": self.user.name,
				"enabled": 1,
			}
		).insert()
		frappe.db.commit()
		self.addCleanup(self._remove_records)

	def _remove_records(self):
		frappe.db.rollback()
		frappe.delete_doc("SSO Service Account", self.mapping.name, delete_permanently=True)
		frappe.db.delete("SSO Identity Assignment Log", {"user": self.user.name})
		frappe.delete_doc("User", self.user.name, delete_permanently=True)
		frappe.db.commit()

	def _token(self, **overrides):
		now = int(time.time())
		claims = {
			"iss": ISSUER,
			"aud": AUDIENCE,
			"azp": self.client_id,
			"sub": self.subject,
			"typ": "Bearer",
			"iat": now,
			"exp": now + 300,
			**overrides,
		}
		return jwt.encode(claims, self.key, algorithm="RS256")

	def _get(self, token, path=WHOAMI, scheme="Bearer"):
		return make_request(
			target=self.client.get,
			args=(path,),
			kwargs={"headers": {"Authorization": f"{scheme} {token}"}, "buffered": True},
			site=frappe.local.site,
		)

	def test_mapped_token_uses_frappe_permissions(self):
		token = self._token()
		reply = self._get(token)
		self.assertEqual(reply.status_code, 200)
		self.assertEqual(reply.json["message"], self.email)
		# get_list requires the doctype argument, exercising form_dict preservation as well as permissions.
		self.assertEqual(
			self._get(
				token, "/api/method/frappe.client.get_list?doctype=SSO%20Service%20Account"
			).status_code,
			403,
		)

	def test_token_requires_signed_access_claims_and_exact_mapping(self):
		for override in (
			{"iss": ISSUER + "-other"},
			{"aud": "another-api"},
			{"exp": 1},
			{"typ": "ID"},
			{"sub": str(uuid4()), "email": self.email},
			{"azp": self.client_id.upper()},
		):
			with self.subTest(override=override):
				self.assertEqual(self._get(self._token(**override)).status_code, 401)
		other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		with patch.object(self, "key", other_key):
			self.assertEqual(self._get(self._token()).status_code, 401)

	def test_revoking_mapping_or_disabling_user_rejects_existing_token(self):
		token = self._token()
		self.mapping.enabled = 0
		self.mapping.save()
		frappe.db.commit()
		self.assertEqual(self._get(token).status_code, 401)
		self.mapping.enabled = 1
		self.mapping.save()
		frappe.db.set_value("User", self.user.name, "enabled", 0)
		frappe.db.commit()
		self.assertEqual(self._get(token).status_code, 401)

	def test_rejects_mapping_to_administrator(self):
		self.mapping.user = "Administrator"
		with self.assertRaises(frappe.ValidationError):
			self.mapping.save()

	def test_native_api_key_still_works_and_service_tokens_require_opt_in(self):
		keys = generate_keys(self.email)
		frappe.db.commit()
		reply = self._get(f"{keys['api_key']}:{keys['api_secret']}", scheme="token")
		self.assertEqual(reply.status_code, 200)
		self.assertEqual(reply.json["message"], self.email)
		self.config["sso_service_token_audience"] = ""
		self.assertEqual(self._get(self._token()).status_code, 401)

	def test_rechecks_roles_and_ip_restrictions(self):
		token = self._token()
		self.user.restrict_ip = "192.0.2.15"
		self.user.save()
		frappe.db.commit()
		self.assertEqual(self._get(token).status_code, 401)
		self.user.restrict_ip = ""
		self.user.add_roles("System Manager")
		frappe.db.commit()
		self.assertEqual(self._get(token).status_code, 401)
