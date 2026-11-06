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
   | 2. GET callback.start with state|                                         |
   |-------------------------------->|                                         |
   |                                 | Create nonce and PKCE verifier          |
   | Set HttpOnly cookie, redirect   | Authorize URL from discovery            |
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
   |                                 | Match state and browser cookie          |
   |                                 | consume_oauth_state(state)              |
   |                                 | 6. POST /token (code, secret, verifier) |
   |                                 |---------------------------------------->|
   |                                 | 7. Return tokens                        |
   |                                 |<----------------------------------------|
   |                                 | Verify ID token signature with JWKS     |
   |                                 | Match immutable ID (sub or oid:tid)     |
   |                                 | oidc_session_authorized = True          |
   |                                 | LoginManager.login_as(user, session_end)|
   | 8. Redirect to /app             |                                         |
   |<--------------------------------|                                         |
```

---

## Core Security Pillars

### 1. Cryptographic ID Token Verification & Issuer Pinning
- **JWKS Signature Verification**: Fetches public signing keys via `PyJWKClient` from the `jwks_uri` in the discovery document of the pinned `sso_issuer`. Sign-in is refused if `sso_issuer` is not set.
- **Strict Claims Verification**: Verifies signature (RS256, ES256, etc.), audience (`client_id`), issuer (`sso_issuer`), expiration (`exp`) and `nonce` using PyJWT.
- **One Browser, One Use**: `state` is single-use and must match an HttpOnly cookie set in the browser that started the sign-in. The code exchange carries the PKCE verifier.

### 2. User Matching by Immutable Identifier
Users are matched using the identity provider's immutable identifier, stored in Frappe's `User Social Login` child table:
- **Keycloak / Generic OIDC**: `sub` claim.
- **Entra ID**: Combined `oid` (Object ID) and `tid` (Tenant ID).

| Identifier | Existing User | Result |
|---|---|---|
| Known | Any email | Signs in. A changed email is logged and the administrators notified; the account is not renamed, as a rename rewrites `owner` and `modified_by` in every table. If another User holds the new email: refused, administrators notified |
| Unknown | Same email, never bound | Binds and logs, only for a verified email: `email_verified` in Keycloak, `xms_edov` in Entra ID |
| Unknown | Same email, bound to another identifier | Refused, logged, administrators notified |
| Unknown | None | Creates the User, bound and with no role, if the Social Login Key allows sign-ups |

Administrator and Guest can never sign in this way, and a disabled user is refused.

### 3. Session Guard (`on_login`)
- Evaluates logins before session creation.
- **Guest**: Allowed (required for logout and setup).
- **CLI Maintenance**: Allowed with no web request behind it (permits `bench browse`), then logged and notified.
- **OIDC Sessions**: Allowed when opened by `handle_callback` (`frappe.flags.oidc_session_authorized`).
- **When `force_sso = 1`**: Blocks every other web session, apart from the break-glass account's.
- **When `force_sso = 0`**: Blocks the same for a User bound to the identity provider or holding an administrative role.

### 4. Absolute Session End
Frappe's **Session Expiry** is an idle timeout: every request pushes it back, so an active session may never end, and someone disabled at the identity provider could keep working. Each session opened by `handle_callback` therefore also ends at a fixed time, which sends the user back through the identity provider.

- **How the end is set**: `handle_callback` computes now in UTC plus **Session Max Lifetime (Hours)** from SSO Identity Settings, and passes it to `LoginManager.login_as(user, session_end=...)` as a timezone-aware ISO string. Frappe stores it with the session; no core change or override is involved.
- **How it is enforced**: Frappe compares it on every request that reads the session from cache, and deletes the session once past it. Activity moves the idle timeout, never this time.
- **Two limits**: Frappe's idle timeout still applies, and whichever limit comes first ends the session. A session idle for longer than Session Expiry ends before its absolute end.
- **New sessions only**: The end is fixed when the session opens. Changing the setting does not move the end of a session already open.

Known limits:
- A session read from the database is not checked. That happens after the cache loses the session; the session goes back to cache after the first successful response, so the next request is checked.
- Frappe does not delete sessions while the site is read-only (`maintenance_mode` with `allow_reads_during_maintenance`), so a session past its end keeps working until read-only mode ends.
- Only sessions opened by `handle_callback` have an end. A password login allowed by the session guard, an API key and a token do not.
- An open socket.io connection is authenticated once, when it connects. It keeps receiving events for the rooms it has joined after its session ends, until it disconnects; see Frappe's `realtime/` code.
