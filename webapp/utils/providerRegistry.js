/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Utils / Provider Registry
 * @tagline         OAuth 2.0 / OIDC provider preset definitions
 * @description     Small registry of provider "presets" (Google, Microsoft Entra ID, generic OIDC, custom OAuth2).
 *                   Admins pick a preset in the config UI; the preset supplies sensible defaults
 *                   and, for OIDC providers, a discovery URL that resolves the rest at runtime.
 * @file            plugins/auth-oauth/webapp/utils/providerRegistry.js
 * @version         1.0.2
 * @release         2026-08-01
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

/**
 * Preset definitions. `type` distinguishes OIDC providers (discovery-driven, ID token issued) from
 * plain OAuth2 providers (manual endpoints, no ID token - see W-197 design doc §2).
 * SVG icons from https://icons8.com/icons
 */
// The well-known 4-color Google "G" mark, used as this preset's default icon. No width/height/x/y
// - every place an icon renders (login button, admin table preview, Connected Accounts) sizes it
// via its own CSS instead, so there's one shape with no baked-in size to fight with. Mirrored (not
// imported - this needs to survive in a plain browser script with no module system) in the config
// UI's client-side renderer, view/jpulse-common.js's `_PRESETS.google.icon`.
const GOOGLE_LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">' +
    '<path fill="#FFC107" d="M43.611,20.083H42V20H24v8h11.303c-1.649,4.657-6.08,8-11.303,8c-6.627,0-12-5.373-12-12c0-6.627,5.373-12,12-12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C12.955,4,4,12.955,4,24c0,11.045,8.955,20,20,20c11.045,0,20-8.955,20-20C44,22.659,43.862,21.35,43.611,20.083z"/>' +
    '<path fill="#FF3D00" d="M6.306,14.691l6.571,4.819C14.655,15.108,18.961,12,24,12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C16.318,4,9.656,8.337,6.306,14.691z"/>' +
    '<path fill="#4CAF50" d="M24,44c5.166,0,9.86-1.977,13.409-5.192l-6.19-5.238C29.211,35.091,26.715,36,24,36c-5.202,0-9.619-3.317-11.283-7.946l-6.522,5.025C9.505,39.556,16.227,44,24,44z"/>' +
    '<path fill="#1976D2" d="M43.611,20.083H42V20H24v8h11.303c-0.792,2.237-2.231,4.166-4.087,5.571c0.001-0.001,0.002-0.001,0.003-0.002l6.19,5.238C36.971,39.205,44,34,44,24C44,22.659,43.862,21.35,43.611,20.083z"/>' +
    '</svg>';

// The classic Microsoft four-square mark. Same "no width/height/x/y" rationale as the Google logo
// above. Mirrored in the config UI's client-side renderer, view/jpulse-common.js's `_PRESETS.microsoft.icon`.
const MICROSOFT_LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">' +
    '<path fill="#ff5722" d="M6 6H22V22H6z"/>' +
    '<path fill="#4caf50" d="M26 6H42V22H26z"/>' +
    '<path fill="#ffc107" d="M26 26H42V42H26z"/>' +
    '<path fill="#03a9f4" d="M6 26H22V42H6z"/>' +
    '</svg>';

export const PROVIDER_PRESETS = {
    google: {
        type: 'oidc',
        label: 'Google',
        icon: GOOGLE_LOGO_SVG,
        buttonColor: '#4285F4',
        discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
        scopes: ['openid', 'email', 'profile'],
        promptForConsent: false,
        requiresClientSecret: true,
        docs: 'https://developers.google.com/identity/protocols/oauth2/openid-connect'
    },
    microsoft: {
        type: 'oidc',
        label: 'Microsoft Entra ID',
        icon: MICROSOFT_LOGO_SVG,
        buttonColor: '#03a9f4',
        // No fixed discoveryUrl (unlike google): Entra ID's discovery document lives under a
        // tenant-specific path (e.g. https://login.microsoftonline.com/<tenant>/v2.0/.well-known/
        // openid-configuration, <tenant> being a domain, GUID, or 'common'/'organizations'/
        // 'consumers') - there's no single URL that works for every org. The admin supplies it,
        // same as the generic 'oidc' preset below. openid-client (utils/oauthClient.js) already
        // special-cases the resulting issuer-template mismatch for login.microsoftonline.com
        // internally, so this "just works" once the admin pastes their tenant's URL - see
        // openid-client's handleEntraId() in its discovery() implementation.
        //
        // KNOWN LIMITATION (v1.0.0, tracked as Gap 5 in the W-197 design doc): Entra ID's ID
        // tokens never carry an `email_verified` claim (Microsoft's own guidance is to never
        // trust its `email` claim for authorization without the separate, non-default `xms_edov`
        // optional claim, which this plugin doesn't request). So oauthAuth.js's
        // `_resolveIdentity()` always computes `emailVerified: false` for this preset, and
        // `_resolveUser()` rejects every Microsoft login under `link-by-email`/`jit-create` with
        // EMAIL_NOT_VERIFIED_AT_PROVIDER. Only `sub-only` works for Microsoft until v1.1.0 adds
        // `xms_edov` support - see docs/README.md's Microsoft Entra ID section.
        scopes: ['openid', 'email', 'profile'],
        requiresClientSecret: true,
        docs: 'https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc'
    },
    oidc: {
        type: 'oidc',
        label: 'OIDC Provider',
        icon: '🔐',
        // #7f8fa6 keeps >=3:1 contrast against both the light (#ffffff) and
        // dark (#2d3748) theme's button background - see webapp/view/auth/login.shtml .local-auth-method
        buttonColor: '#7f8fa6',
        // discoveryUrl is admin-supplied (e.g. https://myorg.okta.com/.well-known/openid-configuration)
        scopes: ['openid', 'email', 'profile'],
        requiresClientSecret: true,
        docs: 'https://openid.net/connect/'
    },
    oauth2: {
        type: 'oauth2',
        label: 'OAuth2 Provider',
        icon: '🔑',
        buttonColor: '#7f8fa6',
        // Admin supplies authorizeUrl, tokenUrl, userinfoUrl, and userinfo -> user field mapping
        scopes: [],
        requiresClientSecret: true
    }
};

/**
 * Look up a preset definition by key.
 * @param {string} presetKey - 'google' | 'microsoft' | 'oidc' | 'oauth2'
 * @returns {object|null} Preset definition, or null if unknown
 */
export function getPreset(presetKey) {
    return PROVIDER_PRESETS[presetKey] || null;
}

/**
 * Whether a preset key is recognized.
 * @param {string} presetKey
 * @returns {boolean}
 */
export function isValidPreset(presetKey) {
    return Object.prototype.hasOwnProperty.call(PROVIDER_PRESETS, presetKey);
}

/**
 * Merge a preset's defaults with an admin-configured provider entry. Provider-level fields
 * (e.g. an overridden `scopes` list) take precedence over the preset's defaults.
 * @param {object} providerConfig - Stored provider entry (see W-197 design doc §8)
 * @returns {object} Effective provider config with preset defaults applied
 */
export function resolveProviderConfig(providerConfig) {
    if (!providerConfig || typeof providerConfig !== 'object') {
        throw new Error('providerRegistry.resolveProviderConfig: providerConfig is required');
    }
    const preset = getPreset(providerConfig.preset);
    if (!preset) {
        throw new Error(`providerRegistry.resolveProviderConfig: unknown preset '${providerConfig.preset}'`);
    }
    return {
        ...preset,
        ...providerConfig,
        scopes: providerConfig.scopes && providerConfig.scopes.length > 0 ? providerConfig.scopes : preset.scopes
    };
}

export default { PROVIDER_PRESETS, getPreset, isValidPreset, resolveProviderConfig };

// EOF plugins/auth-oauth/webapp/utils/providerRegistry.js
