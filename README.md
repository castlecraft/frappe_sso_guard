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
- [04 - Local Development with Keycloak](docs/04-local-development-with-keycloak.md): Running against a real Keycloak in ICRC's dev container template, and the end-to-end test.
- [Review notes for `feat/oidc-callback`](docs/review-notes-feat-oidc-callback.md): What this branch fixes and changes, and where a reviewer's judgement is wanted.

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

- **Entra ID group overage**: a token over Entra ID's limit of groups is refused, rather than read through Graph. See [Team Membership](docs/02-configuration-and-deployment.md#12-team-membership), which also lists what else was left simple.

### Known limits

- **Changing `force_sso`**: it runs no code, so run `bench migrate` after setting it to 1 on a running site. See [Closing the Other Sign-In Paths](docs/02-configuration-and-deployment.md#4-closing-the-other-sign-in-paths).
- **Break-glass account**: the password form stays reachable at `/login?break-glass=1` while an account is named in `sso_break_glass_user`, though only that account can get through it.
- **Absolute session end**: it covers sessions the callback opens, and an open socket.io connection keeps receiving events after its session ends. See [Absolute Session End](docs/01-architecture-and-design.md#4-absolute-session-end).

### Not confirmed yet

- The default absolute session lifetime of 12 hours.
- Whether to refresh each session's tokens with the identity provider, which could replace the session end and most of reconciliation.
- Whether API keys are allowed for people who call the API directly.

### Testing

- Keycloak: `tests/test_keycloak.py` passes against the real Keycloak 26.8.1 container image and against 26.8.1 and 26.6.0 from the zip, and skips where none is running, as in CI. ICRC's dev container stack itself has not yet been started with this app. See [Local Development with Keycloak](docs/04-local-development-with-keycloak.md).
- Entra ID: tested only against a mock. Nothing has been tried against a real tenant.
- `setup_dex` has no tests.
- The pytest suite does not yet cover `api/callback.py` or `services/user_matching.py`; the Frappe suite tests the callback.
- The Frappe tests create users, so they fail with `Throttled` on a site that has just created more than 60 in the last hour, as a volume load does.

## License

MIT
