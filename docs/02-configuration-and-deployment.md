# 02 - Configuration and Deployment Guide

## 1. Prerequisites & Site Config

Add the following keys to your site's `site_config.json`:

```json
{
  "force_sso": 1,
  "sso_issuer": "http://dex.localhost:5556/dex",
  "sso_provider_key": "dex_local"
}
```

### Parameters:
- **`force_sso`** (`1` or `0`):
  - `1`, the default when the key is absent: only the identity provider opens a web session, apart from the break-glass account. See [Closing the Other Sign-In Paths](#4-closing-the-other-sign-in-paths).
  - `0`: For a site whose users include people the identity provider does not know. Others may use a password or email link, but a User bound to the identity provider, or holding System Manager, UCM Administrator or UCM Data Manager, is still refused any session the identity provider did not open. That includes Administrator, on a development or demo site too: use `bench browse`, or name the account in `sso_break_glass_user`.
- **`sso_issuer`** (required): Pinned issuer URL, exactly as the `iss` claim and the discovery document give it. Sign-in is refused without it. The authorization, token and key endpoints all come from this issuer's discovery document, whatever the Social Login Key says.
  - Keycloak: `https://<host>/realms/<realm>`
  - Entra ID: `https://login.microsoftonline.com/<tenant-id>/v2.0`
- **`sso_provider_key`**: Name of the Frappe `Social Login Key` record, when **SSO Identity Settings** names none.
- **`sso_break_glass_user`**: The one account that can use a password. See [Break-Glass Account](#5-break-glass-account).
- **`sso_session_max_hours_limit`**: The longest session the site allows, 12 hours when absent. See [Session Lifetime](#3-session-lifetime).
- **`sso_mfa_values`**, **`sso_mfa_claim`**: The multi-factor authentication a token must show. See [Multi-Factor Authentication](#7-multi-factor-authentication).
- **`sso_directory_client_id`**, **`sso_directory_client_secret`**: The read-only credential for [Reconciliation](#8-reconciliation) and the [API key](#9-api-keys) check.

These are in the site config, not in SSO Identity Settings, because a System Manager can edit the page and these limit what a System Manager can do.

**Identity Provider Type** in SSO Identity Settings selects the immutable identifier: `sub` for Keycloak and Generic OIDC, `oid` with `tid` for Entra ID.

### Identity provider set-up

- Register the callback below as the client's redirect URI. PKCE (S256) must be allowed.
- Register `https://<your-frappe-domain>/login` as a valid post-logout redirect URI.
- Issue tokens to assigned users only: user assignment required in Entra ID, client access limited to its groups in Keycloak.
- Entra ID: add the `email` and `xms_edov` optional claims to the ID token. Without `xms_edov` an existing account cannot be bound, and without `email` no account can be bound or created.

---

## 2. Setting Up Social Login Key

1. Navigate to **Social Login Key** in the Desk.
2. Create or open the record matching `sso_provider_key`:
   - **Provider Name**: e.g. `dex_local`
   - **Base URL**: e.g. `http://dex.localhost:5556/dex`
   - **Custom Base URL**: Off
   - **Authorize URL**: `/api/method/frappe_sso_guard.api.callback.start`. The login page's button goes here first, where the sign-in gets its nonce, PKCE challenge and browser binding.
   - **Access Token URL**: Any value; Frappe requires the field, and the sign-in uses the discovery document's instead.
   - **Sign ups**: `Allow` to create a User at first sign-in, `Deny` to admit only existing accounts. Do not leave it empty: empty follows **Disable Signup** in Website Settings, which section 4 turns on, and would refuse every new person.
   - **Client ID**: Your registered client ID
   - **Client Secret**: Client secret
   - **Redirect URL**: Set to `http://<your-frappe-domain>/api/method/frappe_sso_guard.api.callback.handle_callback`
   - **Authorize URL Data (JSON)**: `{"response_type": "code", "scope": "openid email profile"}`

---

## 3. Session Lifetime

Two settings limit a session opened through single sign-on, and whichever limit comes first ends it:

| Setting | Where | Default | Meaning |
|---|---|---|---|
| **Session Max Lifetime (Hours)** | SSO Identity Settings | 12 | Absolute: hours after sign-in at which the session ends, however active it is |
| **Session Expiry** (`session_expiry`) | System Settings | 170:00 | Idle timeout, as `hh:mm`: every request pushes it back. 240 hours if left empty |

- **Session Max Lifetime (Hours)** must be a whole number of at least 1, and no more than `sso_session_max_hours_limit`; the page refuses anything else, and a value written past the limit by other means is held to it. A change applies to new sessions only: a session already open keeps the end it was given.
- **Session Expiry** cannot switch the idle timeout off: Frappe refuses `0:0`. It ends a session first only when set shorter than Session Max Lifetime, as it is not by default.

See [Absolute Session End](01-architecture-and-design.md#4-absolute-session-end) for how the end is enforced and its known limits.

---

## 4. Closing the Other Sign-In Paths

With `force_sso` at 1, the guard refuses every web session the identity provider did not open, whichever path it comes through. The app also keeps the site in step with it:

- **At install and at each `bench migrate`**, it turns **Login with email link** off, turns **Disable Signup** on, and expires pending User Invitations without emailing anyone. What it changes goes to the identity log as `Site Settings Aligned`.
- **On a save from the web**, it refuses those two settings in any other state. A bench command is left alone, and the next migrate puts them back.

Changing `force_sso` runs no code: after setting it to 1 on a running site, run `bench migrate`. Until then the guard still refuses those paths, but the login page can offer them. Setting it back to 0 restores nothing: change the two settings by hand if the site needs them.

| Path | Closed by |
|---|---|
| `/login` | Redirects to the identity provider, as long as a Social Login Key is set. The form shows only at `/login?break-glass=1`, and only with a break-glass account named |
| Password login | The session guard, for everyone but the break-glass account |
| Email link | **Login with email link** off in System Settings; the session guard refuses a link already sent |
| Sign-up form | **Disable Signup** on in Website Settings |
| Password reset, setting a password | The password guard, for everyone but the break-glass account |
| Welcome email | Switched off on every User |
| User Invitation | Creation refused, pending ones expired; the session guard refuses one already sent |

Leave **Disable Username/Password Login** in System Settings **off**. Frappe applies it to every account before checking the password, so it would also lock out the break-glass account. The password form at `/login?break-glass=1` is therefore only a page: the session guard still refuses everyone but the break-glass account, whatever address they came from.

With `force_sso` at 0, `/login` shows the form again. A User bound to the identity provider or holding an administrative role is still refused any session the provider did not open.

---

## 5. Break-Glass Account

`sso_break_glass_user` in the site config names the one account that can sign in with a password and set one around the identity provider. With none named, nobody can. It takes shell access to set, so a System Manager cannot name themselves:

```bash
bench --site <site-name> set-config sso_break_glass_user <user>
```

- It signs in at `/login?break-glass=1`.
- Give the account its first password from the server: `bench --site <site-name> set-password <user>`, or `set-admin-password` for Administrator.
- Every sign-in by this account is written to the SSO Identity Assignment Log and emailed to **Admin Notification Emails**, so fill that field in.
- Consider two-factor authentication and **Restrict IP** on the account as well.
- Reconciliation never disables it.

---

## 6. Emergency Server Bypass (`bench browse`)

When the identity provider is offline or misconfigured, an operator can log in directly from the site host via the Frappe CLI:

```bash
bench --site <site-name> browse --user Administrator --user-for-audit <operator-name>
```

Every session opened this way is written to the SSO Identity Assignment Log as **Admin CLI Bypass** and emailed to **Admin Notification Emails**.

---

## 7. Multi-Factor Authentication

The identity provider enforces MFA. The callback can also refuse a token that does not show it, which catches a sign-in flow changed at the provider or a client taken out of it:

```json
{
  "sso_mfa_claim": "acr",
  "sso_mfa_values": ["2"]
}
```

- **`sso_mfa_values`**: The accepted values, a list or a single value. Absent, nothing is checked.
- **`sso_mfa_claim`**: The ID token's claim to read, `acr` when absent. A claim holding a list, such as `amr`, passes when any of its values is accepted.
- Keycloak: map the level of authentication to `acr` in the client's flow, and set the same values.
- Entra ID: check what your tenant's tokens carry before setting this. Conditional Access can require MFA with no claim in a v2.0 ID token, and this check would then refuse everyone.

---

## 8. Reconciliation

A job disables in Frappe each bound User the identity provider has disabled or removed. It does not delete them, so their records and audit trail stay, and it ends their sessions.

1. Create a read-only credential at the identity provider, and put it in the site config:
   - Keycloak: a client with a service account holding `view-users`.
   - Entra ID: an application with the Graph application permission `User.Read.All`.
2. Turn on **Enable Reconciliation** in SSO Identity Settings.
3. Use **Run Reconciliation** on that page, or set **Reconciliation Schedule**: Every 15 Minutes, Hourly or Daily.

Safeguards:

- **Every account is read before any is changed.** If the provider fails partway, or refuses the credential, nobody is disabled. The run is logged as **Reconciliation Aborted** and emailed.
- **A run that would disable too many stops.** Past **Stop If More Than (%) Would Be Disabled**, 10 by default, nobody is disabled: a wrong realm answers that every user is gone. Up to five users may always be disabled, so that one person leaving a small site does not stop it. After a real mass departure, raise the percentage for one run.
- The break-glass account and the standard users are never disabled, and Users bound to another provider are not read.

Known limits:

- Entra ID: `accountEnabled` only. A user taken out of the application's assignment gets no more tokens but is not disabled here.
- Each user takes one call to the provider, about 3,000 on a large site. The job fails rather than waits if the provider throttles it, and the next run starts again.

---

## 9. API Keys

An API key opens no session, so neither the session guard nor the session's end applies to it. With `force_sso` at 1, a key from the web is refused unless the User:

- has **Allowed To Hold An API Key** ticked, on the User's API Access section;
- has **Restrict IP** set, to the VPN's ranges;
- holds none of System Manager, Administrator, UCM Administrator and UCM Data Manager.

The same rules refuse those changes on a User who already holds a key. A key created from a bench command is not refused.

Every key created is logged as **API Key Created**. A daily job reports any holder outside the rules as **API Key Alert**, and disables a holder the identity provider has disabled or removed, which ends the key. That check needs the credential in [Reconciliation](#8-reconciliation), but not **Enable Reconciliation**.

---

## 10. Single Logout

With **Enable Single Logout** on, logging out of Frappe also ends the identity provider's session. Otherwise the next visit would sign straight back in.

Frappe's logout answers in JSON, so it marks the browser with a short-lived cookie, and the next `/login` goes to the provider's `end_session_endpoint` first. The provider returns the browser to `/login`.

Known limits:

- Keycloak asks the person to confirm: Frappe keeps no ID token to send as `id_token_hint`.
- A client that logs out and never goes to `/login`, such as Frappe's `web_logout` page, ends the provider's session only on its next visit there, within five minutes.

---

## 11. Audit Log

**SSO Identity Assignment Log** is append-only: no role can create, change or delete an entry, the controller refuses Administrator too, and nothing clears old entries. The requirement is 7 years. Each entry is also written as a structured line to the pod's logs for the SOC, whose copy is the evidence: a database administrator can still change this table.

