# jPulse Framework / Plugins / Auth-OAuth / README v1.0.1

OAuth 2.0 / OpenID Connect (OIDC) single sign-on plugin for jPulse Framework. Supports public sites
(Google) and org-internal sites (Microsoft Entra ID, Okta, Auth0, Keycloak, ADFS via generic OIDC
discovery), plus a manual OAuth2 preset for non-OIDC providers.

## Features

- 🔐 **Authorization Code Flow with PKCE** - mandatory PKCE (S256), state (CSRF), and OIDC nonce on every provider, even confidential clients
- 🏢 **Google + Microsoft Entra ID + Generic OIDC + Custom OAuth2 presets** - Okta, Auth0, Keycloak, ADFS via discovery URL; manual URLs for non-OIDC providers
- 🔗 **Flexible user linking** - `sub-only` (strict), `link-by-email` (default), or `jit-create` (public sites), configurable per provider
- 🛡️ **Composes with MFA** - `auth-mfa`'s TOTP step runs after successful SSO identity resolution via the framework's multi-step login flow
- 🚪 **Break-glass safe** - never locks out admins; works with the framework's `controller.auth.localAuthRestriction`

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
| `jitDefaultRoles` | `['user']` | Roles assigned to JIT-created users, chosen from this site's configured roles (this site's admin roles are always stripped, defense in depth) |
| `jitDefaultStatus` | `active` | `active` (immediate login) or `pending` (admin must approve) |
| `profileRequiredFields` | `['firstName', 'lastName']` | Fields that trigger the profile-completion step for JIT users when the IdP didn't provide them |
| `providers` | `[]` | Identity provider list (managed via the admin UI's provider table) |

See `docs/README.md` for provider setup guides (Google, Microsoft Entra ID, Okta, Keycloak) and the
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
| GET | `/api/1/auth-oauth/admin/assignable-roles` | Admin | This site's roles with admin-equivalent roles removed - backs the JIT role selectors |

## Views

| Path | Purpose |
|------|---------|
| `/auth/oauth-error.shtml` | Error landing page (state mismatch, provider error, etc.) |
| `/auth/oauth-profile-complete.shtml` | Stage B profile completion form for JIT-created users |
| `/jpulse-plugins/auth-oauth.shtml` | User's linked-accounts management page |

## User Schema Extension

This plugin extends the user schema with:

```javascript
{
    oauth: {
        // Keyed by provider id - a dynamic map, one block per linked provider
        [providerId]: {
            sub: String,
            email: String,
            emailVerified: Boolean,
            name: String,
            picture: String,
            iss: String,
            linkedAt: Date,
            lastLoginAt: Date
        },
        // Sentinel marking a JIT-created user - a sibling of provider blocks, not nested
        // inside any single one, since JIT-creation is a property of the user, not a provider
        _jit: {
            createdAt: Date,
            viaProvider: String,
            placeholderFields: Array,
            profileCompletedAt: Date | null
        }
    }
}
```

## Hooks Used

| Hook | Purpose |
|------|---------|
| `onAuthGetLoginProviders` | Inject enabled provider buttons into the login page |
| `onAuthGetSteps` | Insert the `oauth-profile-complete` step for JIT users whose IdP didn't provide all required profile fields |
| `onAuthValidateStep` | Validate/save the `oauth-profile-complete` step submission |

## Security

- Mandatory PKCE (S256) for every provider, even confidential clients
- `state` is one-time-use, 5-minute expiry, stored server-side only (`req.session.oauthPending`)
- OIDC `nonce` verified against the value in the returned ID token
- ID token signature verified via provider JWKS; `iss`/`aud`/`exp` checked
- Client secrets encrypted at rest (`webapp/utils/crypto-secrets.js`), never returned to the admin UI after initial entry
- Only Authorization Code + PKCE — no implicit flow, no resource owner password credentials
- Admin-controlled `label`/`icon`/`buttonColor` fields render raw/unescaped on the login page, so
  they're validated/sanitized server-side on every create/update (not just the admin UI form); the
  config UI reads them back through an attribute-safe escaper, since `jPulse.string.escapeHtml()`
  escapes for element content and leaves `"` intact
- `link-by-email`/`jit-create` require the matched/created local account's email to be verified
  (`emailVerified`) - a matched account with `emailVerified: false` is rejected
  (`LOCAL_EMAIL_NOT_VERIFIED`) rather than linked, and every `jit-create`d account is stamped
  `emailVerified: true` since the IdP already vouched for it; see `docs/README.md`'s Security notes
  for the full explanation

## Requirements

- jPulse Framework >= 1.7.6
- Node.js >= 24.0.0

## Dependencies

- `openid-client` - OAuth 2.0 / OpenID Connect client library (discovery, PKCE, token exchange, ID token verification)

## Plugin Releases

- **Version 1.0.0 - Initial Release**: OAuth 2.0 / OpenID Connect single sign-on with branded
  presets for Google and Microsoft Entra ID, a generic OIDC preset (Okta, Auth0, Keycloak, ADFS, or
  any discovery-URL provider), and a manual OAuth2 preset for non-OIDC providers - multiple
  providers configurable side by side. Three per-provider linking strategies (`sub-only`,
  `link-by-email`, `jit-create`) with `allowedDomains` restriction and dynamic exclusion of this
  site's admin-equivalent roles from JIT role selection (never just hidden in the UI - stripped
  server-side too, sourced from the framework's `getEffectiveAdminRoles()` rather than a hardcoded
  `admin`/`root` list). JIT provisioning with best-effort profile extraction and an interactive
  completion step for fields the IdP didn't supply. Admin provider-management UI is a single live
  table - every edit persists through the framework's one page-level Save Changes button via the
  `onPluginConfigBeforeSave` hook, which also encrypts a newly-entered Client Secret - with computed
  redirect URIs, OIDC discovery testing, and emoji/SVG icon branding. Integrates with the
  framework's `emailVerified` and unique-email primitives (v1.7.6) so `link-by-email`/`jit-create`
  require a verified email, closing an OAuth pre-linking account-takeover. Composes with `auth-mfa`
  via the framework's multi-step login flow. Manually tested end-to-end against a live Google IdP;
  Microsoft Entra ID verified for `sub-only` linking only - see `docs/README.md`'s Microsoft Entra
  ID section for a known `email_verified` limitation affecting `link-by-email`/`jit-create` on that
  preset.
- **Version 1.0.1 - Bugfix**: Fixes the linked-accounts page (`/jpulse-plugins/auth-oauth.shtml`)
  being unreachable from the UI since v1.0.0 - `webapp/view/jpulse-navigation.js` (present in every
  other jPulse plugin, appends a page link to the user menu's "jPulse Plugins" section) was never
  added, so nothing anywhere in the framework's navigation linked to it. Adds a "Connected Accounts"
  entry, matching the `auth-mfa`/`hello-world` pattern - no other behavior changes.

## License

BSL-1.1 - See LICENSE file

## Author

jPulse Team <team@jpulse.net>
