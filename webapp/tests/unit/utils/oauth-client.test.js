/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Tests / Unit / Utils / OAuth Client
 * @tagline         Unit tests for the openid-client wrapper (mocked HTTP - no live IdP)
 * @description     Verifies Configuration caching/invalidation, OIDC issuer derivation from a
 *                   discovery URL, manual Configuration construction for the custom OAuth2
 *                   preset, authorization URL parameter building, and the authorization code
 *                   grant / userinfo delegation - all against a fully mocked `openid-client`
 *                   module (per the W-197 design decision to test mocked-only this session)
 * @file            plugins/auth-oauth/webapp/tests/unit/utils/oauth-client.test.js
 * @version         1.0.4
 * @release         2026-09-30
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import { describe, test, expect, jest, beforeEach } from '@jest/globals';

const mockClient = {
    discovery: jest.fn(),
    Configuration: jest.fn(function Configuration(serverMetadata, clientId, clientSecret) {
        this.serverMetadata = serverMetadata;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }),
    randomPKCECodeVerifier: jest.fn(),
    calculatePKCECodeChallenge: jest.fn(),
    randomState: jest.fn(),
    randomNonce: jest.fn(),
    buildAuthorizationUrl: jest.fn(),
    authorizationCodeGrant: jest.fn(),
    fetchUserInfo: jest.fn()
};

jest.mock('openid-client', () => mockClient);

describe('oauthClient', () => {
    let oauthClient;

    beforeAll(async () => {
        oauthClient = await import('../../../utils/oauthClient.js');
    });

    beforeEach(() => {
        Object.values(mockClient).forEach(fn => typeof fn.mockClear === 'function' && fn.mockClear());
        oauthClient._clearConfigurationCacheForTests();
    });

    describe('getConfiguration - OIDC providers', () => {
        const providerConfig = {
            id: 'google-corp',
            type: 'oidc',
            discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
            clientId: 'client-123',
            clientSecret: 'secret-456'
        };

        test('strips the well-known suffix and calls client.discovery() with the issuer identifier', async () => {
            mockClient.discovery.mockResolvedValue({ fake: 'config' });

            const config = await oauthClient.getConfiguration(providerConfig);

            expect(mockClient.discovery).toHaveBeenCalledTimes(1);
            const [issuerUrl, clientId, clientSecret] = mockClient.discovery.mock.calls[0];
            expect(issuerUrl).toBeInstanceOf(URL);
            expect(issuerUrl.href).toBe('https://accounts.google.com/');
            expect(clientId).toBe('client-123');
            expect(clientSecret).toBe('secret-456');
            expect(config).toEqual({ fake: 'config' });
        });

        test('caches the Configuration - a second call for the same provider does not re-run discovery', async () => {
            mockClient.discovery.mockResolvedValue({ fake: 'config' });

            await oauthClient.getConfiguration(providerConfig);
            await oauthClient.getConfiguration(providerConfig);

            expect(mockClient.discovery).toHaveBeenCalledTimes(1);
        });

        test('invalidateConfiguration() forces the next call to re-run discovery', async () => {
            mockClient.discovery.mockResolvedValue({ fake: 'config' });

            await oauthClient.getConfiguration(providerConfig);
            oauthClient.invalidateConfiguration(providerConfig);
            await oauthClient.getConfiguration(providerConfig);

            expect(mockClient.discovery).toHaveBeenCalledTimes(2);
        });

        test('a different clientId produces a different cache entry (no cross-provider bleed)', async () => {
            mockClient.discovery.mockResolvedValue({ fake: 'config' });

            await oauthClient.getConfiguration(providerConfig);
            await oauthClient.getConfiguration({ ...providerConfig, id: 'google-other', clientId: 'different-client' });

            expect(mockClient.discovery).toHaveBeenCalledTimes(2);
        });
    });

    describe('getConfiguration - custom OAuth2 providers (no discovery)', () => {
        const providerConfig = {
            id: 'custom-provider',
            type: 'oauth2',
            authorizeUrl: 'https://provider.example/authorize',
            tokenUrl: 'https://provider.example/token',
            userinfoUrl: 'https://provider.example/userinfo',
            clientId: 'client-abc',
            clientSecret: 'secret-xyz'
        };

        test('constructs a Configuration manually from admin-supplied endpoints, without calling discovery', async () => {
            const config = await oauthClient.getConfiguration(providerConfig);

            expect(mockClient.discovery).not.toHaveBeenCalled();
            expect(mockClient.Configuration).toHaveBeenCalledTimes(1);
            expect(config.serverMetadata).toMatchObject({
                authorization_endpoint: 'https://provider.example/authorize',
                token_endpoint: 'https://provider.example/token',
                userinfo_endpoint: 'https://provider.example/userinfo'
            });
            expect(config.clientId).toBe('client-abc');
            expect(config.clientSecret).toBe('secret-xyz');
        });
    });

    test('getConfiguration rejects an unsupported provider type', async () => {
        await expect(oauthClient.getConfiguration({ id: 'x', type: 'saml' })).rejects.toThrow();
    });

    describe('PKCE / state / nonce generation', () => {
        test('generatePkce returns a verifier and its derived challenge', async () => {
            mockClient.randomPKCECodeVerifier.mockReturnValue('verifier-value');
            mockClient.calculatePKCECodeChallenge.mockResolvedValue('challenge-value');

            const result = await oauthClient.generatePkce();

            expect(result).toEqual({ codeVerifier: 'verifier-value', codeChallenge: 'challenge-value' });
            expect(mockClient.calculatePKCECodeChallenge).toHaveBeenCalledWith('verifier-value');
        });

        test('generateState delegates to client.randomState', () => {
            mockClient.randomState.mockReturnValue('state-value');
            expect(oauthClient.generateState()).toBe('state-value');
        });

        test('generateNonce delegates to client.randomNonce', () => {
            mockClient.randomNonce.mockReturnValue('nonce-value');
            expect(oauthClient.generateNonce()).toBe('nonce-value');
        });
    });

    describe('buildAuthorizationUrl', () => {
        test('includes PKCE, state, and response_type=code for every provider', () => {
            mockClient.buildAuthorizationUrl.mockReturnValue(new URL('https://idp.example/authorize?x=1'));
            const config = {};

            oauthClient.buildAuthorizationUrl(config, {
                redirectUri: 'https://app.example/api/1/auth-oauth/callback/google-corp',
                scopes: ['openid', 'email', 'profile'],
                state: 'state-value',
                codeChallenge: 'challenge-value'
            });

            expect(mockClient.buildAuthorizationUrl).toHaveBeenCalledWith(config, {
                redirect_uri: 'https://app.example/api/1/auth-oauth/callback/google-corp',
                response_type: 'code',
                scope: 'openid email profile',
                state: 'state-value',
                code_challenge: 'challenge-value',
                code_challenge_method: 'S256'
            });
        });

        test('adds nonce only when provided (OIDC providers)', () => {
            mockClient.buildAuthorizationUrl.mockReturnValue(new URL('https://idp.example/authorize'));
            const config = {};

            oauthClient.buildAuthorizationUrl(config, {
                redirectUri: 'https://app.example/callback',
                scopes: ['openid'],
                state: 's',
                codeChallenge: 'c',
                nonce: 'n'
            });

            expect(mockClient.buildAuthorizationUrl.mock.calls[0][1]).toHaveProperty('nonce', 'n');
        });

        test('omits nonce for the custom OAuth2 preset (no ID token, no nonce)', () => {
            mockClient.buildAuthorizationUrl.mockReturnValue(new URL('https://idp.example/authorize'));
            const config = {};

            oauthClient.buildAuthorizationUrl(config, {
                redirectUri: 'https://app.example/callback',
                scopes: [],
                state: 's',
                codeChallenge: 'c'
            });

            expect(mockClient.buildAuthorizationUrl.mock.calls[0][1]).not.toHaveProperty('nonce');
        });
    });

    describe('exchangeCodeForTokens', () => {
        test('passes pkceCodeVerifier + expectedState, and returns tokens + parsed claims', async () => {
            const fakeTokens = { access_token: 'at', id_token: 'it', claims: jest.fn(() => ({ sub: 'abc123' })) };
            mockClient.authorizationCodeGrant.mockResolvedValue(fakeTokens);
            const config = {};
            const currentUrl = new URL('https://app.example/api/1/auth-oauth/callback/google-corp?code=X&state=Y');

            const result = await oauthClient.exchangeCodeForTokens(config, currentUrl, {
                codeVerifier: 'verifier-value',
                expectedState: 'state-value'
            });

            expect(mockClient.authorizationCodeGrant).toHaveBeenCalledWith(config, currentUrl, {
                pkceCodeVerifier: 'verifier-value',
                expectedState: 'state-value'
            });
            expect(result.tokens).toBe(fakeTokens);
            expect(result.claims).toEqual({ sub: 'abc123' });
        });

        test('includes expectedNonce in the checks when provided (OIDC)', async () => {
            mockClient.authorizationCodeGrant.mockResolvedValue({ claims: jest.fn(() => undefined) });

            await oauthClient.exchangeCodeForTokens({}, new URL('https://app.example/callback'), {
                codeVerifier: 'v',
                expectedState: 's',
                expectedNonce: 'n'
            });

            expect(mockClient.authorizationCodeGrant.mock.calls[0][2]).toEqual({
                pkceCodeVerifier: 'v',
                expectedState: 's',
                expectedNonce: 'n'
            });
        });

        test('claims is undefined when the token response has no claims() helper (custom OAuth2, no ID token)', async () => {
            mockClient.authorizationCodeGrant.mockResolvedValue({ access_token: 'at' });

            const result = await oauthClient.exchangeCodeForTokens({}, new URL('https://app.example/callback'), {
                codeVerifier: 'v',
                expectedState: 's'
            });

            expect(result.claims).toBeUndefined();
        });

        test('propagates rejection on state/PKCE/nonce mismatch (openid-client throws)', async () => {
            mockClient.authorizationCodeGrant.mockRejectedValue(new Error('state mismatch'));

            await expect(oauthClient.exchangeCodeForTokens({}, new URL('https://app.example/callback'), {
                codeVerifier: 'v',
                expectedState: 'wrong'
            })).rejects.toThrow('state mismatch');
        });
    });

    describe('fetchUserInfo', () => {
        test('delegates to client.fetchUserInfo with the expected subject for cross-checking', async () => {
            mockClient.fetchUserInfo.mockResolvedValue({ sub: 'abc123', email: 'jane@example.com' });
            const config = {};

            const result = await oauthClient.fetchUserInfo(config, 'access-token-value', 'abc123');

            expect(mockClient.fetchUserInfo).toHaveBeenCalledWith(config, 'access-token-value', 'abc123');
            expect(result).toEqual({ sub: 'abc123', email: 'jane@example.com' });
        });
    });
});

// EOF plugins/auth-oauth/webapp/tests/unit/utils/oauth-client.test.js
