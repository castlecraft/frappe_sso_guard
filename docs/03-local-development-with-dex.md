# 03 - Local Development with Dex OIDC Provider

This guide explains how to run a local OpenID Connect provider ([Dex](https://github.com/dexidp/dex)) to test `frappe_sso_guard` in a devcontainer.

---

## 1. Devcontainer Configuration

### A. `.devcontainer/docker-compose.yml`
```yaml
  oidc-provider:
    image: dexidp/dex:v2.41.1
    container_name: frappe_sso_dex
    ports:
      - "5556:5556"
    volumes:
      - ../development/frappe-bench/apps/frappe_sso_guard/dev/dex/config.yml:/etc/dex/config.docker.yaml:ro
    restart: unless-stopped

  frappe:
    ...
    extra_hosts:
      - "dex.localhost:host-gateway"
```

---

## 2. Mock Test Users

Pre-configured users in `dev/dex/config.yml` (password is `password` for all):

| Email | Username | Purpose |
|---|---|---|
| `sso-admin@example.org` | `sso-admin` | Admin testing |
| `caseworker@example.org` | `caseworker` | Standard user sign-in |
| `supervisor@example.org` | `supervisor` | Supervisor role testing |

---

## 3. One-Command Setup

From inside the Frappe bench:

```bash
bench --site localhost set-config sso_issuer "http://dex.localhost:5556/dex"
bench --site localhost set-config sso_provider_key "dex_local"
bench --site localhost execute frappe_sso_guard.commands.setup_dex
```

---

## 4. Testing the Login Flow

1. Start your bench (`bench start`).
2. Open `http://localhost:8000/login` in your browser.
3. Click **Login with dex_local**.
4. Log in as `caseworker@example.org` (password: `password`).
5. Dex redirects back to `handle_callback`, verifying the ID token and opening your session in Frappe Desk.
