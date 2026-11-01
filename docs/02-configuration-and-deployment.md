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
  - `1`: Blocks direct username/password logins via the session guard.
  - `0`: Permissive mode for development.
- **`sso_issuer`**: Pinned issuer URL matching the `iss` claim in OIDC tokens and discovery document.
- **`sso_provider_key`**: Name of the Frappe `Social Login Key` record.

---

## 2. Setting Up Social Login Key

1. Navigate to **Social Login Key** in the Desk.
2. Create or open the record matching `sso_provider_key`:
   - **Provider Name**: e.g. `dex_local`
   - **Base URL**: e.g. `http://dex.localhost:5556/dex`
   - **Authorize URL**: `http://dex.localhost:5556/dex/auth`
   - **Access Token URL**: `http://dex.localhost:5556/dex/token`
   - **Client ID**: Your registered client ID
   - **Client Secret**: Client secret
   - **Redirect URL**: Set to `http://<your-frappe-domain>/api/method/frappe_sso_guard.api.callback.handle_callback`
   - **Authorize URL Data (JSON)**: `{"response_type": "code", "scope": "openid email profile"}`

---

## 3. Emergency Server Bypass (`bench browse`)

When the identity provider is offline or misconfigured, an operator can log in directly from the site host via the Frappe CLI:

```bash
bench --site <site-name> browse --user Administrator --user-for-audit <operator-name>
```
