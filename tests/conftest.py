# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

from types import SimpleNamespace
from unittest.mock import MagicMock

import frappe
import pytest

# Every module under test holds its own reference to frappe, so each one is patched where it is used.
MODULES_USING_FRAPPE = (
	"frappe_sso_guard.guard.password_guard",
	"frappe_sso_guard.guard.session_guard",
	"frappe_sso_guard.guard.site_settings",
	"frappe_sso_guard.services.directory",
	"frappe_sso_guard.services.audit",
	"frappe_sso_guard.services.idp",
)


class MockDoc(dict):
	"""A DocType stand-in whose fields read as attributes, and as None when unset, like a real document."""

	def __getattr__(self, name):
		return self.get(name)


@pytest.fixture(autouse=True)
def mock_frappe(mocker):
	"""Replaces frappe in the modules under test, so that no test can need a site, database or Redis."""
	mock = MagicMock()
	mock.conf = {}
	# A MagicMock attribute is truthy, which would pass for a signed-in callback or a live request.
	mock.flags = SimpleNamespace(oidc_session_authorized=False)
	mock.local = SimpleNamespace(http_request=MagicMock())
	mock.PermissionError = frappe.PermissionError
	mock.DoesNotExistError = frappe.DoesNotExistError

	def throw(message, exc=frappe.ValidationError):
		raise exc(message)

	mock.throw.side_effect = throw
	mock.cache.get_value.return_value = None
	mock.get_single.return_value = MockDoc()

	for module in MODULES_USING_FRAPPE:
		mocker.patch(f"{module}.frappe", mock)
		# The real _ reads the session's language, and not every module imports it.
		mocker.patch(f"{module}._", side_effect=lambda message, *args, **kwargs: message, create=True)
	return mock
