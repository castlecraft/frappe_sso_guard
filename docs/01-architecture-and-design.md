# 01 - Architecture and Design

## Overview

`frappe_sso_guard` provides a lightweight, robust OpenID Connect (OIDC) callback and session guard for Frappe v16. It avoids fragile monkey-patching and works directly with Frappe's native OAuth state lifecycle while enforcing strict ID token verification and identity matching.

---

## The Sign-in Flow

```
Browser                     Frappe Desk / Login                     Identity Provider (IdP)
   |                                 |                                         |
   | 1. Click "Login with [IdP]"     |                                         |
   |-------------------------------->|                                         |
   |                                 | create_oauth_state(redirect_to)         |
   | 2. Redirect to IdP Auth URL     |                                         |
   |<--------------------------------|                                         |
   |                                                                           |
   | 3. Authenticate with IdP                                                  |
   |-------------------------------------------------------------------------->|
   |                                                                           |
   | 4. Redirect to handle_callback with code & state                          |
   |<--------------------------------------------------------------------------|
   |                                                                           |
   | 5. GET /api/method/frappe_sso_guard.api.callback.handle_callback          |
   |-------------------------------->|                                         |
   |                                 | consume_oauth_state(state)              |
   |                                 | 6. POST /token (code + secret)          |
   |                                 |---------------------------------------->|
   |                                 | 7. Return tokens                        |
   |                                 |<----------------------------------------|
   |                                 | Verify ID token signature with JWKS     |
   |                                 | Match immutable ID (sub or oid:tid)     |
   |                                 | oidc_session_authorized = True          |
   |                                 | LoginManager.login_as(user)             |
   | 8. Redirect to /app             |                                         |
   |<--------------------------------|                                         |
```

---

## Core Security Pillars

### 1. Cryptographic ID Token Verification & Issuer Pinning
- **JWKS Signature Verification**: Fetches public signing keys via `PyJWKClient` from the pinned `sso_issuer` (`/keys` or `/.well-known/openid-configuration`).
- **Strict Claims Verification**: Verifies signature (RS256, ES256, etc.), audience (`client_id`), issuer (`sso_issuer`), and expiration (`exp`) using PyJWT.

### 2. User Matching by Immutable Identifier
Users are matched using the identity provider's immutable identifier, stored in Frappe's `User Social Login` child table:
- **Keycloak / Generic OIDC**: `sub` claim.
- **Entra ID**: Combined `oid` (Object ID) and `tid` (Tenant ID).

If the user does not exist in Frappe:
- If an existing user holds the email, the identifier is bound to that account.
- If no user holds the email, a new User document is created with the identifier bound.

### 3. Session Guard (`on_login`)
- Evaluates logins before session creation.
- **Guest**: Allowed (required for logout and setup).
- **CLI Maintenance**: Allowed when `frappe.local.http_request` is `None` (permits `bench browse`).
- **OIDC Sessions**: Allowed when opened by `handle_callback` (`frappe.flags.oidc_session_authorized`).
- **When `force_sso = 1`**: Blocks direct username/password logins.
