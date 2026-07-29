/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Utils / Provider Registry
 * @tagline         OAuth 2.0 / OIDC provider preset definitions
 * @description     Small registry of provider "presets" (Google, generic OIDC, custom OAuth2).
 *                   Admins pick a preset in the config UI; the preset supplies sensible defaults
 *                   and, for OIDC providers, a discovery URL that resolves the rest at runtime.
 * @file            plugins/auth-oauth/webapp/utils/providerRegistry.js
 * @version         1.0.0
 * @release         2026-07-29
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

/**
 * Preset definitions. `type` distinguishes OIDC providers (discovery-driven, ID token issued) from
 * plain OAuth2 providers (manual endpoints, no ID token - see W-197 design doc §2).
 */
export const PROVIDER_PRESETS = {
    google: {
        type: 'oidc',
        label: 'Google',
        icon: '🇬',
        buttonColor: '#4285F4',
        discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
        scopes: ['openid', 'email', 'profile'],
        promptForConsent: false,
        requiresClientSecret: true,
        docs: 'https://developers.google.com/identity/protocols/oauth2/openid-connect'
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
        icon: '🔗',
        buttonColor: '#7f8fa6',
        // Admin supplies authorizeUrl, tokenUrl, userinfoUrl, and userinfo -> user field mapping
        scopes: [],
        requiresClientSecret: true
    }
};

/**
 * Look up a preset definition by key.
 * @param {string} presetKey - 'google' | 'oidc' | 'oauth2'
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
