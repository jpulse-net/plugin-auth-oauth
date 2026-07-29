# jPulse Framework / Plugins / Auth-OAuth / README v1.0.0

OAuth 2.0 / OpenID Connect (OIDC) single sign-on plugin for jPulse Framework. Supports public sites
(Google) and org-internal sites (Okta, Auth0, Azure Entra, Keycloak, ADFS via generic OIDC discovery),
plus a manual OAuth2 preset for non-OIDC providers.

> **Status: work in progress.** This plugin is being built out incrementally against
> `docs/dev/design/W-197-auth-oauth-plugin.md`. See "Implementation Status" below for what's
> implemented so far vs. still pending.

## Features

- 🔐 **Authorization Code Flow with PKCE** - mandatory PKCE (S256), state (CSRF), and OIDC nonce on every provider, even confidential clients
- 🏢 **Google + Generic OIDC + Custom OAuth2 presets** - Okta, Auth0, Azure Entra, Keycloak, ADFS via discovery URL; manual URLs for non-OIDC providers
- 🔗 **Flexible user linking** - `sub-only` (strict), `link-by-email` (default), or `jit-create` (public sites), configurable per provider
- 🛡️ **Composes with MFA** - `auth-mfa`'s TOTP step runs after successful SSO identity resolution via the framework's multi-step login flow (W-109)
- 🚪 **Break-glass safe** - never locks out admins; works with the framework's `controller.auth.localAuthRestriction` (W-195)

## Installation

```bash
npx jpulse plugin install auth-oauth --registry=https://npm.pkg.github.com
npx jpulse plugin enable auth-oauth
```

## Configuration

Configure via Admin UI at `/admin/plugins/auth-oauth` or via plugin config API.

### Global Settings

| Setting | Default | Description |
|---------|---------|--------------|
| `defaultLinkingStrategy` | `link-by-email` | Fallback linking strategy for providers that don't override it |
| `jitDefaultRoles` | `['user']` | Roles assigned to JIT-created users (`admin`/`root` are always stripped, defense in depth) |
| `jitDefaultStatus` | `active` | `active` (immediate login) or `pending` (admin must approve) |
| `profileRequiredFields` | `['firstName', 'lastName']` | Fields that trigger the profile-completion step for JIT users when the IdP didn't provide them |
| `providers` | `[]` | Identity provider list (managed via the admin UI's provider table) |

See `docs/README.md` for provider setup guides (Google, Okta, Keycloak, Azure Entra) and the
migration walkthrough for moving an existing internal-auth site to SSO.

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|--------------|
| GET | `/api/1/auth-oauth/providers` | None | List enabled providers for login button rendering |
| GET | `/api/1/auth-oauth/init/:provider` | None | Start OAuth flow, redirect to provider's authorize endpoint |
| GET | `/api/1/auth-oauth/callback/:provider` | None | Handle provider callback, complete or continue auth |
| GET | `/api/1/auth-oauth/user/providers` | User | List providers linked to the authenticated user |
| POST | `/api/1/auth-oauth/link/:provider` | User | Start link flow (connect an additional provider) |
| DELETE | `/api/1/auth-oauth/link/:provider` | User | Unlink a provider from the authenticated user |
| GET | `/api/1/auth-oauth/profile-draft` | None (pending-auth session) | Prefill data for the Stage B `oauth-profile-complete` step - see `docs/README.md` |
| GET | `/api/1/auth-oauth/admin/providers` | Admin | List all configured providers (no secrets) |
| POST | `/api/1/auth-oauth/admin/providers` | Admin | Create a new provider config |
| PUT | `/api/1/auth-oauth/admin/providers/:id` | Admin | Update provider config |
| DELETE | `/api/1/auth-oauth/admin/providers/:id` | Admin | Delete provider config |
| POST | `/api/1/auth-oauth/admin/providers/:id/test` | Admin | Force OIDC discovery refresh |

## Views

| Path | Purpose |
|------|---------|
| `/auth/oauth-error.shtml` | Error landing page (state mismatch, provider error, etc.) |
| `/auth/oauth-profile-complete.shtml` | Stage B profile completion form for JIT-created users |
| `/jpulse-plugins/auth-oauth.shtml` | User's linked-accounts management page |

## Implementation Status

Tracking against `docs/dev/design/W-197-auth-oauth-plugin.md`:

- [x] `providerRegistry.js` — Google / generic OIDC / custom OAuth2 presets
- [x] `oauthClient.js` — openid-client wrapper (discovery, PKCE, state/nonce, ID token verification)
- [x] `oauthProvider.js` — provider config CRUD + client secret encryption at rest
- [x] `oauthAuth.js` controller — `apiProviders`, `apiInit`, `apiCallback` (state/nonce/PKCE validation, token exchange, ID token verification, rate limiting)
- [x] Basic user resolution in the callback: `sub-only` and `link-by-email` strategies
- [x] `/auth/oauth-error.shtml` — error landing page with a short-code → friendly-message map
      (client-side; **no i18n** yet — see note below)
- [x] Unit tests for all of the above (`crypto-secrets`, `providerRegistry`, `oauthClient`,
      `oauthProvider`, `oauthAuth` — 141 tests, all dependencies mocked, no live IdP calls)
- [x] `onAuthGetLoginProviders` hook (login page buttons) + provider config caching (§13,
      short-TTL Redis cache in front of `OauthProviderModel.getProviders()`)
- [x] User schema extension (W-107 admin/user cards) in `model/oauthAuth.js`
- [x] Link/unlink endpoints + unlink-last-method guard (`apiUserProviders`/`apiLink`/`apiUnlink`)
- [x] Linked-accounts page (`/jpulse-plugins/auth-oauth.shtml`)
- [x] `jit-create` linking strategy + `profileExtractor.js` (Stage A best-effort claim extraction) —
      creates a schema-conformant user immediately, with username-collision retry and a
      concurrent-creation race fallback (design doc §9 edge case)
- [x] `oauth-profile-complete` Stage B step (`onAuthGetSteps`/`onAuthValidateStep`, injected into
      the existing W-109 multi-step login flow) + view — only fires when the IdP didn't provide
      all `profileRequiredFields`
- [x] W-194 custom renderer for the admin provider table (`jpulse-common.js`) + the dedicated
      `admin/providers*` CRUD/test endpoints it calls — client secrets are encrypted server-side
      before ever touching `pluginConfigs`, and never round-trip back to the browser
- [x] Provider field hardening: `buttonColor` (6-digit hex only), `label` (rejects `<`/`>`), and
      `icon` (plain text/emoji pass through; markup is run through the framework's allow-list
      sanitizer so only inert single-color SVG shapes can survive) — these three fields render
      raw/unescaped on the login page, so this is enforced server-side in `apiAdminProvidersCreate`/
      `apiAdminProvidersUpdate`, not just in the admin UI form
- [ ] i18n (`en`/`de`) — **no plugin-level i18n mechanism exists in the framework yet** (found
      during this phase: `webapp/translations/*.conf` only loads framework/site strings); all
      plugin-facing strings are English-only until that framework gap is addressed
- [x] Full README polish + `docs/README.md` provider setup guides (Google, Okta, Keycloak, Azure
      Entra), migration walkthrough (Paths A/B), and the site-mode config table (§12)
- [x] Manual smoke test in a running dev server (admin plugin config UI - General/Providers/Security
      tabs, custom provider table - verified against a running instance)
- [ ] Manual test pass against a real IdP (deferred — this session used mocked HTTP only)
- [ ] Published to `github.com/jpulse-net/plugin-auth-oauth`

## Security

- Mandatory PKCE (S256) for every provider, even confidential clients
- `state` is one-time-use, 5-minute expiry, stored server-side only (`req.session.oauthPending`)
- OIDC `nonce` verified against the value in the returned ID token
- ID token signature verified via provider JWKS; `iss`/`aud`/`exp` checked
- Client secrets encrypted at rest (`webapp/utils/crypto-secrets.js`), never returned to the admin UI after initial entry
- Only Authorization Code + PKCE — no implicit flow, no resource owner password credentials
- Admin-controlled `label`/`icon`/`buttonColor` fields render raw/unescaped on the login page, so
  they're validated/sanitized server-side on every create/update (not just the admin UI form)

See `docs/dev/design/W-197-auth-oauth-plugin.md` for the full design, threat model, and migration
guidance.
