# frappe_sso_guard: review notes for `feat/oidc-callback`

**Base:** `4fe952a` (`version-16`). **Head:** `6b076b5`, plus the commit adding this file. 19 commits, 61 files, +6,482 / -568. If you read the earlier `2f9132e`, start at section 3: 7 commits are new.

**Note:** section 1 describes weaknesses in the code on `version-16`, which is still unfixed until this branch is merged.

**State:** ready for review. Pushed, with no pull request yet, so CI has not run. It now runs against a real Keycloak, in ICRC's dev container template on Frappe 16.35.0. Entra ID is still tested only against a mock.

## 1. Problems in `4fe952a` that this fixes

| Problem | Effect | Fixed in |
|---|---|---|
| `force_sso` does not block password login. `on_login` runs inside `HTTPRequest()`, before `frappe.local.http_request` is assigned, so the guard's CLI bypass matches every `/api/method/login`. Shown with a probe on Frappe 16.52.0 | Anyone with a password gets past single sign-on | `9ca71ea` |
| The callback binds a user by unverified email | A token carrying someone's email can take over that account | `926acb5` |
| The callback reads the JWKS from `{issuer}/keys`, a path Dex serves, not the discovery document's `jwks_uri` | Not a weakness, but verification cannot work on Keycloak or Entra ID | `926acb5` |
| No nonce, PKCE or browser binding on the sign-in | A callback can be forged or replayed, or finished in another browser | `926acb5` |
| The callback's `error` parameter reaches Frappe's message page unescaped | Script injection on an endpoint open to guests | `926acb5` |
| Sessions have no absolute end, and `guard/session_expiry.py`, which nothing calls, would fail open: a naive-against-aware comparison raises into `except Exception: pass` | An active session may never end | `926acb5`; the module is removed |
| A System Manager can create an API key for anyone | A standing way around the identity provider | `e40fdc6` |
| The inactive users report puts names in HTML as they are | HTML injection in an email to administrators | `1eae1da` |
| The identity log is cleared after 90 days | Falls short of the 7 years and append-only rule in ICRC's access control NFR | `59a263a` |

## 2. The commits you have seen, oldest first

| Commit | Change |
|---|---|
| `59a263a` | Identity log is append-only and out of Frappe's log clearing; every event also goes to stdout for the SOC |
| `926acb5` | Callback does the code exchange with PKCE, a nonce and browser-bound state; verifies signature, issuer, audience and expiry against `sso_issuer` in the site config; matches on `sub`, or `oid` with `tid` on Entra ID; sets `session_end`, which a System Manager can only shorten; optional MFA claim check |
| `9ca71ea` | Session guard recognises a login inside a web request; password guard closes reset keys, welcome emails, invitations and setting a password; one break-glass account |
| `2e0867d` | `/login` goes to the provider through `update_website_context`; logout ends the provider's session |
| `ad1e719` | Reconciliation disables users the provider has disabled or removed, by hand or on a schedule, and aborts past a set share |
| `e40fdc6` | API keys only for flagged users with Restrict IP and no admin role, logged and checked daily |
| `1eae1da` | Report escapes names and moves off raw SQL |
| `6cc05c8` | pytest suite mocking Frappe, beside Frappe's own tests, as PBI 712133 asks |
| `a4408d3` | Docs: the sign-in, settings and limits |
| `84fa3de` | Install and migrate turn email link off, Disable Signup on and expire pending invitations; web saves undoing those settings are refused |
| `a552d3e` | Frappe tests no longer leave rows behind |
| `2f9132e` | README status brought up to date |

## 3. New since `2f9132e`

| Commit | Change |
|---|---|
| `b062a5e` | `setup_keycloak`, a test realm holding no credentials, and `dev/keycloak/forward.py` |
| `c786e91` | `tests/test_keycloak.py`: the whole sign-in through Keycloak's real pages. It skips where no Keycloak runs, as in CI. Real discovery and token claims saved as fixtures now check the mock |
| `c3c8e4e` | Docs: running against Keycloak |
| `e8c2bfd` | Sets a person's teams from their groups at sign-in, before the session opens. Off by default |
| `7e83908` | Test from real Keycloak groups to a real UCM Team, where UCM is installed |
| `03b7bc4` | Docs: team membership |
| `6b076b5` | Warning on the settings page while a schedule is set and Frappe's scheduler is off |

**Suggested reading order for these:** `services/team_membership.py`, the `handle_callback` hunk in `api/callback.py`, then `commands.py`.

**The team membership hooks.** An app holding teams names a function in `sso_set_user_teams`, and this app offers `ucm_team_membership_from_idp`, so neither app needs the other. UCM's side is in a separate pull request to `icrc/frappe_prot_ucm_core`, not yet raised.

**What a real Keycloak showed that mocks could not:**

- It sends no `groups` claim for someone in no group, not an empty list. A missing claim therefore means no groups, unless `_claim_names` says the groups are elsewhere, as Entra ID does for someone with too many; that person is refused.
- `acr` is `1` on a fresh sign-in and `0` when reusing Keycloak's session, so `sso_mfa_values` of `1` would refuse someone already signed in to another application.
- Its issuer follows the address it is called on, and ICRC's template has two addresses: `localhost:8080` for the browser and `keycloak:8080` for the bench. The realm's `frontendUrl` does not help, as it moves the token and key endpoints too. `forward.py` is the answer for development, and production has one address.
- Logout takes two clicks, as the app keeps no ID token to send as a hint.

## 4. Where your judgement is wanted

1. **Administrator and passwords.** You advised against locking Administrator out of password login. With `force_sso` on or off, administrative roles, Administrator included, are refused a password unless named in `sso_break_glass_user`. `bench browse` still works. The comments on 731827 had a settings page naming the account; it moved to the site config, because a System Manager could otherwise name themselves.
2. **`force_sso` defaults to on.** A site without the key has its settings changed and invitations expired at install or migrate. ICRC's `create-site.sh` installs every app, so a site made that way is forced from install unless `force_sso` is set to 0 bench-wide first.
3. **Frappe's Disable Username/Password Login stays off.** It would lock out the break-glass account, so the guard blocks passwords instead. The wiki design says to turn it on.
4. **A changed email is logged, not copied to the User.** The design says copy, but `User.validate` resets `email` to `name`, and a rename rewrites `owner` and `modified_by` in every table.
5. **Single logout uses a cookie.** Frappe's logout answers in JSON and cannot redirect, so a short-lived cookie sends the next `/login` to `end_session_endpoint` first. Is there a cleaner route?
6. **Reconciliation's cron runs every 15 minutes.** It does nothing unless enabled and due. ICRC asked for a cronjob or webhook; the design proposed by hand only.
7. **Metadata.** File headers I touched now name the ICRC, while `hooks.py` still has `app_publisher` as ICRC / Castlecraft and your email. It is your repository: which do you want?
8. **New accounts do not require a verified email.** Binding to an existing account does. When Sign ups is `Allow`, an unverified address gets a new account, and with team membership on, its groups can give it a team's access. Left this way for now by decision. Requiring it is a small change, but Keycloak users created by hand may need marking verified.
9. **The site settings guard refuses every web save of System Settings while email link is on.** Setting `force_sso` to 1 without the documented `bench migrate` leaves it on, which broke Frappe's setup wizard in the test. Left this way for now by decision. It could refuse only a change that turns it on.
10. **Team membership choices, all the simplest for now:** a team naming a group takes its members from the provider alone; a change applies at the next sign-in; no group naming convention; the log is the existing DocType, not the Team's version history. A mapper removed by mistake takes people out of these teams as they sign in, which fails safe, and they return once it is restored.

## 5. Not done

- **Entra ID group overage:** such a token is refused, rather than read through Graph (731832).
- **A real Entra ID tenant, and real MFA:** the test realm has no second factor, so the MFA check ran as a comparison of the claim only.
- **Open socket.io connections** keep receiving events after the session ends: Frappe authenticates them once, at connection. Read in the code, not run.
- **Known gaps in the session end:** a session read from the database skips one check, and Frappe does not delete sessions while the site is read-only.
- **Token refresh, and the 12-hour default:** open questions for ICRC.
- **Frappe's `on_social_login` hook** (frappe/frappe PR 46198, backport 46233): not evaluated. Frappe 16.52.0 does not have it, and it may let the callback shrink.
- **ICRC's private dev stack, and a Windows laptop:** the public template ran on a Linux host, with local changes for its ports, two image names and DNS.

**One unexplained failure.** `test_second_sign_in_finds_the_person_by_identifier_after_their_email_changes` failed with a 403 in 2 of about 30 runs on 16.52.0, before a test client bug was fixed. 8 clean full runs and the run on 16.35.0 followed, but the reason was never captured, so a real sign-in problem is not ruled out. Its failure message now shows the reason, so please look if it appears in CI.

## 6. Running the tests

```bash
bench setup requirements --dev        # for freezegun
bench --site <site> set-config allow_tests true
bench --site <site> run-tests --app frappe_sso_guard
pip install -e ".[ci]" && pytest      # from the app's folder, needs no site
```

`test_keycloak` also needs a Keycloak running and `KEYCLOAK_PASSWORD`; `docs/04-local-development-with-keycloak.md` has how.

| Where | Result |
|---|---|
| ICRC's template, Frappe 16.35.0, Keycloak 26.8.1, at `03b7bc4` | 199 Frappe tests passed with none skipped, 117 pytest, and a real browser 9 of 9 |
| Same stack, Frappe's own scheduler running reconciliation | Passed: one run; the 15-minute repeat was not observed |
| Frappe 16.52.0 at `6b076b5`, with no Keycloak running | 184 Frappe tests passed with `test_keycloak` skipped, 117 pytest, pre-commit clean |

`6b076b5` has not run on 16.35.0. On a site that created more than 60 users in the last hour, the Frappe tests fail with `Throttled`.
