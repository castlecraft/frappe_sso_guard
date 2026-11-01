# Frappe SSO Guard

Lightweight, robust OIDC Single Sign-On (SSO) guard app for Frappe v16.

---

## Key Features

- **Strict SSO Enforcement (`force_sso = 1`)**: Shuts down standard password logins at the `on_login` hook while accommodating `Guest` and CLI maintenance (`bench browse`).
- **Cryptographic ID Token Verification**: Verifies ID token signatures against the pinned issuer's JWKS (`sso_issuer`) using PyJWT (`PyJWKClient`).
- **Immutable User Matching**: Matches users by provider immutable identifiers (`sub` or `oid:tid`) in Frappe's `User Social Login` table.
- **Native State Lifecycle**: Leverages Frappe's native OAuth state caching (`consume_oauth_state`), avoiding fragile custom cookies or page overrides.

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

```bash
bench --site <site-name> set-config allow_tests true
bench --site <site-name> run-tests --app frappe_sso_guard
```

## License

MIT
