# Frappe SSO Guard

Lightweight, robust OIDC Single Sign-On (SSO) guard app for Frappe v16.

---

## Key Features

- **Strict SSO Enforcement (`force_sso = 1`)**: Refuses every web session the identity provider did not open, at the `on_login` hook, and refuses setting a password, while accommodating `Guest`, CLI maintenance (`bench browse`) and one named break-glass account.
- **Cryptographic ID Token Verification**: Verifies ID token signatures against the JWKS in the pinned issuer's discovery document (`sso_issuer`) using PyJWT (`PyJWKClient`), with Keycloak and Entra ID alike.
- **Immutable User Matching**: Matches users by provider immutable identifiers (`sub` or `oid:tid`) in Frappe's `User Social Login` table. An existing account is bound only through an email the identity provider verified.
- **Bound Sign-In**: Adds a nonce, PKCE and a browser-bound cookie to Frappe's single-use OAuth state, with no page overrides.
- **No Other Way In**: `/login` goes to the identity provider, and reset keys, email links and invitations are refused.
- **Single Logout**: Logging out of Frappe also ends the identity provider's session.
- **Reconciliation**: Disables Users the identity provider has disabled or removed, by hand or on a schedule, and stops if the answer looks wrong.
- **API Key Controls**: Keys only for flagged Users held to the VPN, logged, and checked daily against the identity provider.
- **Append-Only Audit**: Every event in a log nothing clears, and as a structured line for the SOC.

---

## Documentation

Detailed guides are available in the [`docs/`](docs/) directory:

- [01 - Architecture and Design](docs/01-architecture-and-design.md): Sequence flow, ID token verification, user matching, and session guard.
- [02 - Configuration and Deployment Guide](docs/02-configuration-and-deployment.md): Setting up `site_config.json`, Social Login Key, and CLI emergency bypass (`bench browse`).
- [03 - Local Development with Dex OIDC Provider](docs/03-local-development-with-dex.md): Walkthrough of running the local Dex OIDC service via `dev/docker-compose.dex.yml` and testing logins.

---

## Local Development & Mock IdP

A pre-configured Dex OIDC setup is available under [`dev/`](dev/) to test the SSO flow locally:

- Compose service: [`dev/docker-compose.dex.yml`](dev/docker-compose.dex.yml)
- Dex config & mock users: [`dev/dex/config.yml`](dev/dex/config.yml)
- Walkthrough: [Local Development with Dex Guide](docs/03-local-development-with-dex.md)

---

## Installation

```bash
bench get-app frappe_sso_guard
bench --site <site-name> install-app frappe_sso_guard
```

## Running Tests

The app has two independent suites, and neither runner collects the other's tests.

**Frappe tests** need a site. They follow Frappe's layout: a DocType's rules in `test_<doctype>.py` beside its controller, everything else in `frappe_sso_guard/tests/`.

```bash
bench --site <site-name> set-config allow_tests true
bench --site <site-name> run-tests --app frappe_sso_guard
bench --site <site-name> run-tests --app frappe_sso_guard --test-category unit
```

**Pytest tests** live in `tests/` at the repository root. Frappe is mocked, so they need no site, database or network. Run them from the app's folder with the bench's Python:

```bash
pip install -e ".[ci]"
pytest                          # everything
pytest -m security              # sign-in and token checks only
pytest --cov=frappe_sso_guard   # with coverage
```

## Status

This app is still being built. Check the following before relying on it.

### Not built yet

- **Reconciliation**: disabling in Frappe the users the identity provider has disabled or removed. Until then, such a user cannot sign in again, but stays enabled in Frappe and keeps any session already open until it ends.
- **Single logout**: logging out of Frappe does not end the identity provider's session, so the next visit can sign the user straight back in.
- **Group mapping**: setting a user's teams from the groups in their token, including Entra ID group overage.
- **Expiring pending invitations**: invitations sent before the app was installed stay pending, although the session guard refuses the sign-in they lead to.

### Settings with no effect yet

These appear in **SSO Identity Settings**, but switching them does nothing:

| Setting | What controls it today |
|---|---|
| **Enable SSO Guard** | `force_sso` in `site_config.json` |
| **Enable Single Logout (SLO)** | Nothing; see above |
| **Enable Reconciliation** | Nothing; see above |

### Known limits

- **Login page**: it still shows the password form, which only the break-glass account can get through. See [Closing the Other Sign-In Paths](docs/02-configuration-and-deployment.md#4-closing-the-other-sign-in-paths) for this and for the settings each site must change by hand.
- **Break-glass account**: any System Manager can change it. The change is logged and emailed, and the email goes out only if **Admin Notification Emails** is filled in.

### Not confirmed yet

- The default absolute session lifetime of 12 hours.
- Whether to refresh each session's tokens with the identity provider, which could replace the session end and most of reconciliation.
- Whether API keys are allowed for people who call the API directly.

### Testing

- The tests use a mock identity provider. Sign-in has not yet been confirmed by hand against a real Keycloak or Entra ID, and there are no browser tests.
- The scheduled tasks in `tasks/` and the commands in `commands.py` have no tests.
- The pytest suite does not yet cover `api/callback.py` or `services/user_matching.py`; the Frappe suite tests the callback.

## License

MIT
