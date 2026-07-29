/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Utils / OAuth Client
 * @tagline         openid-client (v6, functional API) wrapper: discovery, PKCE, state/nonce, ID token verification
 * @description     Thin wrapper around openid-client that (a) caches discovered/constructed
 *                   Configuration objects per provider so we don't re-run OIDC discovery on every
 *                   request, and (b) exposes the small surface this plugin actually needs
 *                   (build authorization URL, exchange code for tokens, verify ID token claims,
 *                   optionally fetch userinfo). See W-197 design doc §2-3.
 * @file            plugins/auth-oauth/webapp/utils/oauthClient.js
 * @version         1.0.0
 * @release         2026-07-29
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import * as client from 'openid-client';

// Configuration objects are meant to be reused across requests (openid-client caches JWKS/
// discovery internally on the instance) - cache by provider id + a fingerprint of the fields
// that would require a fresh Configuration if they changed (discoveryUrl/clientId/endpoints).
const configurationCache = new Map();

function cacheKey(providerConfig) {
    return [
        providerConfig.id,
        providerConfig.type,
        providerConfig.discoveryUrl || '',
        providerConfig.authorizeUrl || '',
        providerConfig.tokenUrl || '',
        providerConfig.userinfoUrl || '',
        providerConfig.clientId
    ].join('|');
}

/**
 * Derive the OIDC Issuer Identifier from a discovery URL, stripping the well-known suffix so we
 * can use `client.discovery()`'s RECOMMENDED issuer-identifier form (which validates the returned
 * `issuer` claim) rather than pointing it directly at the discovery document (which openid-client
 * supports but explicitly does NOT recommend, since it skips that validation).
 * @param {string} discoveryUrl
 * @returns {string} Issuer identifier URL
 */
function issuerFromDiscoveryUrl(discoveryUrl) {
    return discoveryUrl.replace(/\/\.well-known\/openid-configuration\/?$/, '');
}

/**
 * Get (or build/cache) an openid-client Configuration for a provider.
 * @param {object} providerConfig - Resolved provider config (see providerRegistry.resolveProviderConfig()),
 *   with `clientSecret` already decrypted (see oauthProvider.getProviderWithSecret())
 * @returns {Promise<client.Configuration>}
 */
export async function getConfiguration(providerConfig) {
    const key = cacheKey(providerConfig);
    if (configurationCache.has(key)) {
        return configurationCache.get(key);
    }

    let config;
    if (providerConfig.type === 'oidc') {
        const issuer = issuerFromDiscoveryUrl(providerConfig.discoveryUrl);
        config = await client.discovery(new URL(issuer), providerConfig.clientId, providerConfig.clientSecret);
    } else if (providerConfig.type === 'oauth2') {
        // No discovery document - server metadata is admin-supplied (design doc §2: "Custom OAuth2").
        // `issuer` has no real meaning here; openid-client requires the field to be present, so we
        // synthesize a stable, provider-scoped value that is never used for cross-provider validation.
        const serverMetadata = {
            issuer: `urn:jpulse:auth-oauth:${providerConfig.id}`,
            authorization_endpoint: providerConfig.authorizeUrl,
            token_endpoint: providerConfig.tokenUrl,
            userinfo_endpoint: providerConfig.userinfoUrl
        };
        config = new client.Configuration(serverMetadata, providerConfig.clientId, providerConfig.clientSecret);
    } else {
        throw new Error(`oauthClient.getConfiguration: unsupported provider type '${providerConfig.type}'`);
    }

    configurationCache.set(key, config);
    return config;
}

/** Drop a cached Configuration (e.g. after "Test Connection" forces a fresh discovery, §2). */
export function invalidateConfiguration(providerConfig) {
    configurationCache.delete(cacheKey(providerConfig));
}

/** Test-only: clear the entire Configuration cache so unit tests don't leak state between cases. */
export function _clearConfigurationCacheForTests() {
    configurationCache.clear();
}

/**
 * Generate the PKCE (S256) code verifier + challenge pair for one authorization request.
 * @returns {Promise<{ codeVerifier: string, codeChallenge: string }>}
 */
export async function generatePkce() {
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    return { codeVerifier, codeChallenge };
}

/** Generate a fresh, one-time-use `state` value (CSRF protection, design doc §3/Security Requirements). */
export function generateState() {
    return client.randomState();
}

/** Generate a fresh, one-time-use OIDC `nonce` value (replay protection for the ID token). */
export function generateNonce() {
    return client.randomNonce();
}

/**
 * Build the provider's authorization URL to redirect the browser to.
 * @param {client.Configuration} config
 * @param {object} params - { redirectUri, scopes, state, codeChallenge, nonce? }
 * @returns {URL}
 */
export function buildAuthorizationUrl(config, { redirectUri, scopes, state, codeChallenge, nonce }) {
    const parameters = {
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: (scopes || []).join(' '),
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
    };
    if (nonce) {
        parameters.nonce = nonce;
    }
    return client.buildAuthorizationUrl(config, parameters);
}

/**
 * Exchange an authorization code for tokens, validating `state` (and `nonce` for OIDC providers)
 * along the way. Mirrors the security invariants in the W-197 design doc §3/Security Requirements:
 * PKCE code_verifier never leaves the server, state is one-time-use, nonce is checked against the
 * verified ID token.
 * @param {client.Configuration} config
 * @param {URL} currentUrl - The full callback URL (including query string) the provider redirected to
 * @param {object} checks - { codeVerifier, expectedState, expectedNonce? }
 * @returns {Promise<{ tokens: object, claims: object|undefined }>}
 */
export async function exchangeCodeForTokens(config, currentUrl, { codeVerifier, expectedState, expectedNonce }) {
    const checks = { pkceCodeVerifier: codeVerifier, expectedState };
    if (expectedNonce) {
        checks.expectedNonce = expectedNonce;
    }
    const tokens = await client.authorizationCodeGrant(config, currentUrl, checks);
    return { tokens, claims: tokens.claims?.() };
}

/**
 * Fetch the userinfo endpoint (optional step - only needed when ID token claims alone aren't
 * sufficient, or for the non-OIDC 'oauth2' preset which has no ID token at all).
 * @param {client.Configuration} config
 * @param {string} accessToken
 * @param {string} [expectedSubject] - When known (from ID token `sub`), openid-client cross-checks it
 * @returns {Promise<object>} Parsed userinfo JSON
 */
export async function fetchUserInfo(config, accessToken, expectedSubject) {
    const response = await client.fetchUserInfo(config, accessToken, expectedSubject);
    return response;
}

export default {
    getConfiguration,
    invalidateConfiguration,
    generatePkce,
    generateState,
    generateNonce,
    buildAuthorizationUrl,
    exchangeCodeForTokens,
    fetchUserInfo
};

// EOF plugins/auth-oauth/webapp/utils/oauthClient.js
