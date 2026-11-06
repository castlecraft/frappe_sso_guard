# 04 - Local Development with Keycloak

This guide runs the app against a real Keycloak in [icrc-frappe-devcontainer-template](https://github.com/icrc/icrc-frappe-devcontainer-template), which ships one. Nothing in the template changes: its `frappe` realm stays as it is, and the app adds a realm of its own.

**What was run, and what was not.** The test below and a run in a real browser pass against Keycloak 26.8.1, the template's version, in the template's image `quay.io/keycloak/keycloak:26.8.1`, with the bench in a separate container reaching it through `forward.py`. They also pass against 26.8.1 and 26.6.0 run from Keycloak's zip. The template's own Compose stack has **not** been started, so its service names and the steps in section 2 have not been run there. Entra ID has no local equivalent and is tested only against a mock.

---

## 1. The address of the issuer

Keycloak names its issuer after the address it is called on, and the template gives it two:

| Who calls | Address | Issuer Keycloak reports |
|---|---|---|
| The browser, on the host | `http://localhost:8080` | `http://localhost:8080/realms/...` |
| The bench, in its container | `http://keycloak:8080` | `http://keycloak:8080/realms/...` |

The app pins one issuer and refuses any other, as it must. So the bench has to call Keycloak by the browser's address, and [`dev/keycloak/forward.py`](../dev/keycloak/forward.py) makes `localhost:8080` reach `keycloak:8080` inside the bench's container. Setting the realm's `frontendUrl` does not solve this: it moves the token and key endpoints to `localhost` too, where the bench cannot reach them.

Production has one address for everyone and needs none of this.

## 2. In the dev container

Add the app to `development/apps.json`, and fetch it with `./get-apps.sh`. Install it on a site that already has `force_sso` at `0`, if the site is to keep password logins: without the key the app treats the site as forced, and install turns the email link off, turns sign-ups off and expires pending invitations.

```bash
bench --site dev.localhost set-config force_sso 0
bench --site dev.localhost install-app frappe_sso_guard
```

Leave the forwarder running in a terminal of its own:

```bash
cd /workspace/development/frappe-bench
python apps/frappe_sso_guard/dev/keycloak/forward.py
```

Then, in another:

```bash
cd /workspace/development/frappe-bench
export KEYCLOAK_PASSWORD="$(grep '^KEYCLOAK_PASSWORD=' /workspace/.devcontainer/.env | cut -d= -f2-)"
bench --site dev.localhost execute frappe_sso_guard.commands.setup_keycloak
```

`setup_keycloak` works only in developer mode. It:

- creates the `frappe-sso-guard` realm from [`dev/keycloak/realm.json`](../dev/keycloak/realm.json), replacing it if it exists, with new secrets and a new password, which it prints;
- creates the Social Login Key `keycloak_local` and selects it in **SSO Identity Settings**;
- sets `sso_issuer`, `sso_directory_client_id` and `sso_directory_client_secret` in the site config.

Open `http://dev.localhost:8000/login` and use **Login with keycloak_local**, or set `force_sso` to `1` to be sent straight there.

**Frappe's web processes keep the site config for 60 seconds.** A change to `force_sso` or `sso_issuer` can take that long to apply on a running server, and this holds in production too.

## 3. The people in the realm

| Username | Purpose |
|---|---|
| `sso.active` | Signs in |
| `sso.disabled` | Keycloak refuses them |
| `sso.unverified` | Their email is not verified: the app refuses to bind them to an existing account |
| `sso.leaver` | Disable or delete them in Keycloak, then run a reconciliation |

The realm also holds `frappe-sso-guard-directory`, a service account with only `view-users`, which reconciliation uses.

## 4. The test

[`frappe_sso_guard/tests/test_keycloak.py`](../frappe_sso_guard/tests/test_keycloak.py) goes through Keycloak's real pages: sign-in, refusals, a replayed callback, logout and reconciliation. It creates and deletes its own realm, and leaves your `frappe-sso-guard` realm alone.

```bash
bench --site dev.localhost set-config allow_tests true
bench --site dev.localhost run-tests --app frappe_sso_guard --module frappe_sso_guard.tests.test_keycloak
```

It needs `KEYCLOAK_PASSWORD` and a Keycloak at `KEYCLOAK_URL` (default `http://localhost:8080`, so the forwarder must be running). Without either it skips, which is how CI runs it. CI's own proof is the mock in `test_callback.py`, kept honest by the real responses saved in [`frappe_sso_guard/tests/fixtures/`](../frappe_sso_guard/tests/fixtures/).

## 5. Without a container

Keycloak needs Java 21 and no root:

```bash
export KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD="<a password of your own>"
bin/kc.sh start-dev --http-port=8080
```

Add `--http-management-port` with a free port if the bench's realtime server holds 9000. The bench and the browser then share `localhost:8080`, so no forwarder is needed. Set `KEYCLOAK_PASSWORD` to the same password and go on from `setup_keycloak`.

## 6. What Keycloak showed

- **Logging out takes two clicks.** Keycloak asks "Do you want to log out?", because the request carries no ID token and the app does not keep one.
- **`acr` is `1` for a password sign-in and `0` when the sign-in reuses Keycloak's session**, as when someone is already signed in to another application. So `sso_mfa_values` set to `1` refuses the second case. The test realm has no second factor, so the check was run as a comparison of the claim only: the values for ICRC's realm have to come from how MFA is set up there.
