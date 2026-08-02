# jPulse Framework / Plugins / Auth-OAuth / User Documentation v1.0.2

Adds "Sign in with..." buttons to your login page for OAuth 2.0 / OpenID Connect identity providers
(Google, Microsoft Entra ID, Okta, Auth0, Keycloak, ADFS, or any generic OIDC/OAuth2 provider).

## Quick start

1. Install and enable the plugin (see `README.md`)
2. Go to `/admin/plugins/auth-oauth` → "Providers" tab → **+ Add Provider**
3. Pick a preset (Google / Microsoft Entra ID / OIDC Provider / OAuth2 Provider), fill in the
   Client ID/Secret, and (for the Microsoft/OIDC presets) the identity provider's discovery URL
4. Copy the computed **Redirect URI** shown in the form into your identity provider's console -
   this is the exact callback URL the IdP needs to allow (see the per-provider guides below)
5. Click the page's own **Save Changes** button to persist it - the "Sign in with..." button then
   appears on `/auth/login.shtml`

Every field in the provider form updates the table above it immediately as you type - there's
nothing to click to "add" or "confirm" a provider edit beyond filling in the fields. **Save Changes**
is the only action that actually persists anything, exactly like every other setting on this page.

Every provider gets its own row in the table, so you can run several side by side (e.g. Google for
public signup and an internal Okta tenant for staff).

### Branding a provider button

Three fields control how a provider looks. All are optional - leave any of them blank and the
preset's own default is used (the form shows that default as the field's placeholder, and the table
shows an inherited value in grey):

| Field | Where it shows up |
|---|---|
| **Label** | The text on the "Sign in with..." button on `/auth/login.shtml`, and the provider name on each user's Connected Accounts page |
| **Icon** | Next to that label in both places. An emoji (`🔐`) or a small inline SVG - paste the `<svg>...</svg>` markup itself, not an image URL. The table's "Icon & Label" column previews it as you type. The Google and Microsoft Entra ID presets already ship with their own logo, so this field is usually only needed for the OIDC/OAuth2 presets |
| **Button Color** | The border color of that provider's button on the login page. It's deliberately just the border - the button keeps the site theme's background so it stays readable in both light and dark mode |

An inline SVG is sanitized server-side down to inert shape elements (`svg`, `path`, `g`, `circle`,
`rect`, `line`, `polyline`, `polygon` and their geometry/fill attributes); scripts, event handlers,
external references, and anything else are stripped before it's stored. The icon is displayed at a
fixed size, so it doesn't matter what `width`/`height` the SVG you paste declares.

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

Google's console UI is called "Google Auth Platform" (it replaced the older single-page "OAuth
consent screen"). Its steps have a natural chicken-and-egg wrinkle - the redirect URI you need to
give Google depends on the provider id you choose in jPulse, but jPulse needs a Client ID/Secret
from Google first. The order below avoids that: create the Google client with no redirect URI yet,
get your credentials immediately, then come back and add the URI once you know it.

1. In the [Google Cloud Console](https://console.cloud.google.com), pick or create a project (top
   left project picker). If you're on a Google Workspace domain, creating the project under your
   org (instead of "No organization") unlocks the "Internal" audience option in the next step.
2. **Google Auth Platform → Audience**: choose an audience type.
   - **Internal** (only available for projects under a Workspace org) - restricts sign-in to your
     own domain's accounts, with no "unverified app" warning screen and no test-user allowlist.
     The easiest option if this is an org-internal deployment.
   - **External** - needed for public Gmail accounts. Stays in **Testing** mode (up to 100 manually
     added test users, unverified-app warning shown to them) until you complete Google's app
     verification for **Production** use - verification isn't required for the `openid`/`email`/
     `profile` scopes this plugin uses (they're non-sensitive), but the warning screen still shows
     until the app is verified or you're testing as an added test user.
3. **Google Auth Platform → Branding**: fill in the required fields (App name, User support email,
   Developer contact email). This is required before Google lets you create a client, even though
   it's Google's own end-user-facing consent screen, not anything jPulse-specific.
4. **Google Auth Platform → Clients → + Create client**:
   - Application type: **Web application**
   - Leave "Authorized redirect URIs" empty for now and click **Create**. Google shows the
     **Client ID** and **Client Secret** immediately - copy both. (Redirect URIs can always be
     added to an existing client later; they don't need to be set at creation time.)
5. In `/admin/plugins/auth-oauth`, add a provider with preset **Google**, paste the Client ID and
   Client Secret from step 4. No discovery URL is needed - Google's is built into the preset.
6. Copy the computed **Redirect URI** now shown in the jPulse form. Go back to **Google Auth
   Platform → Clients**, open the client from step 4, add that URL under "Authorized redirect
   URIs", and save.
7. Scopes default to `openid email profile`, which is enough to get a verified email and name.
8. Optional, recommended for Workspace domains: set the provider's **Allowed Domains** field (e.g.
   `example.com`) as a second layer of restriction on top of the Internal audience setting.

For local development, `http://localhost:<port>` (no HTTPS) is an accepted redirect URI value -
Google explicitly allows plain HTTP for `localhost`/`127.0.0.1` so you don't need TLS just to test.

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

### Microsoft Entra ID (formerly Azure AD)

> **Known limitation (v1.0.0): set this provider's Linking Strategy to `sub-only`.** Entra ID's ID
> tokens never include an `email_verified` claim (Microsoft's own recommendation is to never trust
> its `email` claim for authorization decisions - see Security notes below), so `link-by-email`/
> `jit-create` reject every Microsoft login with "email not verified", even for a real, matching
> account. This fails closed (nothing gets incorrectly linked), but it means those two strategies
> don't work at all for this preset yet. `sub-only` doesn't depend on email verification and works
> normally - it just means an admin has to create each user's local account first (or the user has
> to link via Path B below after logging in locally once).

**If your organization already uses Microsoft 365 / Entra ID** (you have a work/school account),
skip to step 1 below. **If you don't** - Microsoft retired the old "register an app under just my
personal account" option in June 2024, so a personal Microsoft account by itself is no longer
enough; you need your own tenant first. The reliable free option for anyone is an **Azure free
account**, which provisions a Microsoft Entra ID tenant automatically as part of signup - no
separate "sandbox" product to qualify for:

1. Go to [azure.microsoft.com/free](https://azure.microsoft.com/free) and sign up with any
   Microsoft account (personal is fine) - Microsoft requires a phone number and a credit or debit
   card for identity verification (a temporary ~$1 authorization hold that's automatically
   reversed; the free tier itself is never charged)
2. Signup automatically creates a Microsoft Entra ID Free tenant for you, under a new
   `<something>.onmicrosoft.com` domain that you own and administer - no extra step needed
3. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com) with that same
   account - you're now inside a real directory and app registration works

(The Microsoft 365 Developer Program's free "Instant sandbox" is **not** a reliable alternative for
this: as of this writing Microsoft restricts it to Visual Studio Professional/Enterprise
subscribers, ISV Success Program / Microsoft AI Cloud Partner Program members, or organizations
with a Premier/Unified Support contract - a plain new Microsoft account is shown a "Register an
application" screen instead of the sandbox option. If you already qualify for one of those
programs, it works just as well as the Azure free account path above; if you don't, use Azure free
instead.)

From here the steps are the same regardless of which path above got you a directory:

1. Go to Microsoft Entra ID → App registrations → New registration
2. Under "Supported account types", **Single tenant only** is enough unless you specifically want
   people from other organizations (or personal Microsoft accounts) to sign in too
3. Leave "Redirect URI" empty for now and click **Register** - same chicken-and-egg reasoning as
   the Google guide above: the URI depends on the provider id you choose in jPulse, which doesn't
   exist yet
4. Copy the **Application (client) ID** from the app's Overview page
5. Under "Certificates & secrets", create a new client secret and copy its value immediately (it's
   only shown once)
6. Your discovery URL is `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration`,
   where `<tenant-id>` is your tenant's GUID or verified domain name (both shown on the app's
   Overview page and on Entra ID → Overview) - or `common`/`organizations`/`consumers` instead of a
   tenant id if you chose a multi-tenant "Supported account types" option in step 2
7. In `/admin/plugins/auth-oauth`, add a provider with preset **Microsoft Entra ID**, and fill in
   the Client ID, Client Secret, and Discovery URL from the steps above
8. Copy the computed **Redirect URI** now shown in the jPulse form, go back to the app's
   **Authentication** page, **+ Add a platform → Web**, paste it in, and save

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
JIT-created accounts default to the "JIT: Default Roles" setting, which offers a choice from this
site's configured roles (Admin UI → General tab) for each provider to override individually via
"JIT: Override Roles" - this site's admin roles can never be auto-assigned this way, even by a
misconfiguration. Use "JIT: Default Status" to require admin approval before a JIT-created account
can log in. Since none of this applies to a provider using `sub-only` or `link-by-email`, the
per-provider "JIT: Override Roles"/"JIT: Status" fields only appear in that provider's edit form
when its effective Linking Strategy (its own override, or the inherited global default above) is
JIT create.

## Security notes

- Every provider uses Authorization Code flow with mandatory PKCE - no implicit flow
- Client secrets are encrypted at rest and never sent back to the browser after you save them once
- `state` and (for OIDC) `nonce` protect every login round-trip; sessions started but not completed
  within 5 minutes expire automatically
- **`link-by-email`/`jit-create` require the matched local account's email to be verified.** The
  framework enforces DB-level, lowercase-normalized email uniqueness and tracks an `emailVerified`
  field on every user (as of v1.7.6); this plugin's `link-by-email` branch refuses to link a
  matched local account whose `emailVerified` is explicitly `false` (reason code
  `LOCAL_EMAIL_NOT_VERIFIED`), and every `jit-create`d account is stamped `emailVerified: true`
  since the IdP itself already vouched for that address. This closes an account-takeover exploit
  chain that used to exist: previously an attacker could sign up locally using a target's real
  email address, and the target's first legitimate SSO login would silently attach to the
  attacker's account instead of creating a fresh one. Accounts created before v1.7.6 have no
  `emailVerified` field at all and are treated as grandfathered/verified (a missing field, not an
  explicit `false`, doesn't block linking) - if your deployment has long-lived local accounts you
  don't fully trust the email address on, review them before enabling `link-by-email`/`jit-create`.
  The framework's own signup/profile-edit flow still doesn't send a verification email itself (a
  full verify-your-email UX is on the roadmap), so a **brand-new** local account today starts
  `emailVerified: false` and stays that way until an admin manually flips it (`emailVerified` is
  an admin-editable user field) - which is exactly the fail-closed behavior this plugin relies on.
- **Microsoft Entra ID does not support `link-by-email`/`jit-create` in this release.** Unlike every
  other supported IdP, Entra ID's ID tokens never carry an `email_verified` claim - by design, since
  Microsoft's own guidance is that its `email` claim is admin-settable per user and should never be
  trusted for authorization decisions without a separate, non-default optional claim (`xms_edov`)
  that this plugin doesn't request yet. So `identity.emailVerified` is always computed as `false` for
  Microsoft, and `link-by-email`/`jit-create` reject every Microsoft login with "email not verified"
  before ever attempting to match or create a user - fail-closed, not a security hole, but the two
  strategies simply don't work for this preset. Use `sub-only` for Microsoft providers until a future
  release adds `xms_edov` support. Google and OIDC providers that do supply a trustworthy
  `email_verified` are unaffected.
