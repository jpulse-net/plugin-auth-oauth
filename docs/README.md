# jPulse Framework / Plugins / Auth-OAuth / User Documentation v1.0.0

Adds "Sign in with..." buttons to your login page for OAuth 2.0 / OpenID Connect identity providers
(Google, Okta, Auth0, Azure Entra, Keycloak, ADFS, or any generic OIDC/OAuth2 provider).

## Quick start

1. Install and enable the plugin (see `README.md`)
2. Go to `/admin/plugins/auth-oauth` → "Providers" tab → **+ Add Provider**
3. Pick a preset (Google / OIDC Provider / OAuth2 Provider), fill in the Client ID/Secret, and
   (for the OIDC preset) the identity provider's discovery URL
4. Copy the computed **Redirect URI** shown in the form into your identity provider's console -
   this is the exact callback URL the IdP needs to allow (see the per-provider guides below)
5. Save - the "Sign in with..." button appears on `/auth/login.shtml`

Every provider gets its own row in the table, so you can run several side by side (e.g. Google for
public signup and an internal Okta tenant for staff).

## Provider setup guides

Each guide below assumes you already have admin access to the identity provider's console.
The **Redirect URI** to paste into the IdP is always:

```
https://your-domain.example/api/1/auth-oauth/callback/<provider-id>
```

where `<provider-id>` is the id you chose for the provider row (e.g. `google-corp`). The admin UI
shows this computed value (with a "Copy" button) right in the provider form once you've typed an
id, so you never have to build it by hand.

### Google

1. Go to the [Google Cloud Console](https://console.cloud.google.com/apis/credentials) → APIs &
   Services → Credentials
2. Create (or reuse) an **OAuth 2.0 Client ID** of type "Web application"
3. Under "Authorized redirect URIs", add the Redirect URI from above
4. Copy the generated **Client ID** and **Client Secret**
5. In `/admin/plugins/auth-oauth`, add a provider with preset **Google**, paste the Client ID and
   Client Secret. No discovery URL is needed - Google's is built into the preset.
6. Scopes default to `openid email profile`, which is enough to get a verified email and name.

### Okta

1. In the Okta Admin Console, go to Applications → Create App Integration → OIDC - Web Application
2. Add the Redirect URI from above under "Sign-in redirect URIs"
3. Copy the **Client ID** and **Client Secret** from the app's General tab
4. Your discovery URL is `https://<your-org>.okta.com/.well-known/openid-configuration` (or your
   custom domain's equivalent)
5. In `/admin/plugins/auth-oauth`, add a provider with preset **OIDC Provider**, and fill in the
   Client ID, Client Secret, and Discovery URL from the steps above

### Keycloak (self-hosted / air-gapped friendly)

1. In the Keycloak Admin Console, select your realm → Clients → Create client
2. Client type: OpenID Connect; enable "Client authentication" (confidential client)
3. Under "Valid redirect URIs", add the Redirect URI from above
4. Copy the **Client ID**; find the **Client Secret** under the client's Credentials tab
5. Your discovery URL is `https://<your-keycloak-host>/realms/<realm>/.well-known/openid-configuration`
6. In `/admin/plugins/auth-oauth`, add a provider with preset **OIDC Provider** and the three
   values above. Keycloak works entirely on your own network - no external calls needed.

### Azure Entra ID (formerly Azure AD)

1. In the Azure Portal, go to Microsoft Entra ID → App registrations → New registration
2. Add the Redirect URI from above as a "Web" platform redirect URI
3. Under "Certificates & secrets", create a new client secret and copy its value immediately (it's
   only shown once)
4. Copy the **Application (client) ID**
5. Your discovery URL is `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration`
6. In `/admin/plugins/auth-oauth`, add a provider with preset **OIDC Provider** and the values above

### Any other OIDC provider (Auth0, ADFS, etc.)

Use the **OIDC Provider** preset with that provider's discovery URL - anything that publishes a
standard `/.well-known/openid-configuration` document works the same way as the guides above.

### Non-OIDC providers (plain OAuth2)

If a provider has no OIDC discovery document (no ID token, just an OAuth2 authorize/token/userinfo
triplet), use the **OAuth2 Provider** preset instead. You supply the Authorize URL, Token URL, and
Userinfo URL manually, plus a "Userinfo Mapping" - a small JSON object that tells the plugin which
field in that provider's userinfo response corresponds to `sub`/`email`/`name`, e.g.:

```json
{ "sub": "id", "email": "primary_email", "name": "display_name" }
```

## Migrating an existing site from local accounts to SSO

If your site already has users signing in with username/password and you want to add (or switch
to) SSO, there's no bulk migration step required - existing users link automatically or
self-service, in order of how much admin effort each needs:

### Path A - Automatic (zero admin work)

With the default `link-by-email` strategy, an existing user's *first* SSO login automatically
attaches the provider identity to their existing account, as long as:

- Their local `email` matches the email the IdP returns, and
- The IdP reports that email as verified (`email_verified: true`)

They keep their existing roles, profile, and preferences - nothing else changes. This works out of
the box for Google Workspace / Entra deployments where the corporate email is the same as the SSO
email.

### Path B - Self-service link (when Path A doesn't apply)

If the emails don't match (e.g. a personal Gmail address vs. a corporate local account), the user
can link explicitly instead:

1. Log in normally with the local username/password
2. Go to `/jpulse-plugins/auth-oauth.shtml` (linked accounts page)
3. Click "Connect" next to the provider
4. Complete the provider's login screen

This also works for admins during the initial migration, before restricting local auth.

### Finishing the migration

Once enough users have linked their accounts (via A or B), lock local login down to admins only,
so everyone else must use SSO going forward, while keeping a recovery path for operators:

```
webapp/app.conf: controller.auth.localAuthRestriction = "admins-only"
```

Admin accounts can still sign in with a local password. `/auth/login.shtml?localFallback=1` remains
available as an emergency recovery path if SSO itself is ever unreachable.

## Choosing a site mode

None of the settings below live in this plugin's config - they're all framework-level
(`webapp/app.conf`), documented here so you can pick the right combination in one place instead of
piecing it together from several docs.

| Site mode | `controller.user.disableSignup` | `view.auth.hideSignup` | `controller.auth.localAuthRestriction` | Recommended linking strategy |
|---|---|---|---|---|
| **Company SSO** (internal IdP only, no public signup) | `true` | `true` | `admins-only` | `sub-only` or `link-by-email`; leave JIT off |
| **Public signup via SSO** (SSO *is* the signup flow) | `true` | `true` | `none` | `jit-create` |
| **Migration** (transitional - both local and SSO work while users link, see above) | `false` | `false` | `none`, then `admins-only` once migrated | `link-by-email` |
| **SSO as a convenience** (local signup stays open; SSO is optional) | `false` | `false` | `none` | `jit-create` or `link-by-email` |

`localAuthRestriction: 'admins-only'` (and even `'disabled'`) always preserves admin break-glass
access and the `?localFallback=1` recovery path - this plugin can never lock you out of your own
site.

## Just-in-time (JIT) account creation

With `jit-create`, a brand-new local account is created automatically the first time someone signs
in via SSO and no existing account matches. If the identity provider didn't supply a first/last
name (some providers only send an email), the new user is asked to confirm their name on a short
one-time screen right after their first login - existing users are never asked this. Roles for
JIT-created accounts default to the "JIT: Default Roles" setting (Users only - `admin`/`root` can
never be auto-assigned this way, even by a misconfiguration); use "JIT: Default Status" to require
admin approval before a JIT-created account can log in.

## Security notes

- Every provider uses Authorization Code flow with mandatory PKCE - no implicit flow
- Client secrets are encrypted at rest and never sent back to the browser after you save them once
- `state` and (for OIDC) `nonce` protect every login round-trip; sessions started but not completed
  within 5 minutes expire automatically
