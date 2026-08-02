/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Tests / Unit / Controller / OAuth Auth
 * @tagline         Unit tests for OauthAuthController
 * @description     Tests apiProviders (listing), the onAuthGetLoginProviders hook, apiInit
 *                   (state/nonce/PKCE generation + redirect), apiCallback (state validation, token
 *                   exchange, user resolution via sub-only/link-by-email/jit-create strategies,
 *                   account status checks, and handoff to AuthController.completeExternalAuth() -
 *                   plus its 'link' mode branch), the authenticated
 *                   apiUserProviders/apiLink/apiUnlink endpoints, the jit-create Stage B
 *                   multi-step pieces (onAuthGetSteps, onAuthValidateStep, apiProfileDraft), and
 *                   the admin provider CRUD/test endpoints backing the W-194 custom renderer
 *                   (apiAdminProviders, apiAdminProvidersCreate/Update/Delete/Test). All
 *                   framework dependencies (OauthProviderModel, OauthAuthModel, oauthClient,
 *                   UserModel, PluginModel, AuthController) are mocked - this file exercises
 *                   OauthAuthController's own logic only.
 * @file            plugins/auth-oauth/webapp/tests/unit/controller/oauth-auth.test.js
 * @version         1.0.2
 * @release         2026-08-01
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.13, Claude Sonnet 5
 */

import { describe, test, expect, jest, beforeAll, beforeEach } from '@jest/globals';
import CommonUtils from '../../../../../../webapp/utils/common.js';
import { getPreset } from '../../../utils/providerRegistry.js';

// Jest hoists jest.mock() factories above imports and forbids them from closing over
// out-of-scope variables unless the variable name starts with "mock" (case-insensitive).
const mockState = {
    providers: [],
    providerWithSecret: null,
    userFindResult: [],
    pluginDoc: null,
    userById: null,
    linkedProviders: [],
    canUnlinkResult: { allowed: true },
    findUserByProviderSubResult: null,
    createdUser: null,
    createError: null,
    providerById: null,
    upsertedConfig: null,
    adminRoles: ['admin', 'root'],
    siteRoles: ['user', 'admin', 'root']
};

jest.mock('../../../model/oauthProvider.js', () => ({
    __esModule: true,
    default: {
        getProviders: jest.fn(async () => mockState.providers),
        getCachedProviders: jest.fn(async () => mockState.providers),
        getProviderWithSecret: jest.fn(async () => mockState.providerWithSecret),
        getProviderById: jest.fn(async () => mockState.providerById),
        setClientSecret: jest.fn(async (id) => `ref:authOauth_providers/${id}/clientSecret`),
        deleteClientSecret: jest.fn(async () => true),
        invalidateCachedProviders: jest.fn(async () => undefined)
    }
}));

jest.mock('../../../model/oauthAuth.js', () => ({
    __esModule: true,
    default: {
        initialize: jest.fn(),
        listLinkedProviders: jest.fn(() => mockState.linkedProviders),
        canUnlinkProvider: jest.fn(() => mockState.canUnlinkResult),
        unlinkProvider: jest.fn(async () => true),
        findUserByProviderSub: jest.fn(async () => mockState.findUserByProviderSubResult)
    }
}));

jest.mock('../../../utils/oauthClient.js', () => ({
    __esModule: true,
    generatePkce: jest.fn(async () => ({ codeVerifier: 'test-code-verifier', codeChallenge: 'test-code-challenge' })),
    generateState: jest.fn(() => 'test-state'),
    generateNonce: jest.fn(() => 'test-nonce'),
    getConfiguration: jest.fn(async () => ({
        __fakeConfig: true,
        serverMetadata: () => ({
            issuer: 'https://idp.example.com',
            authorization_endpoint: 'https://idp.example.com/authorize',
            token_endpoint: 'https://idp.example.com/token',
            userinfo_endpoint: 'https://idp.example.com/userinfo',
            jwks_uri: 'https://idp.example.com/jwks'
        })
    })),
    invalidateConfiguration: jest.fn(),
    buildAuthorizationUrl: jest.fn(() => new URL('https://idp.example.com/authorize?state=test-state')),
    exchangeCodeForTokens: jest.fn(async () => ({ tokens: { access_token: 'test-access-token' }, claims: undefined })),
    fetchUserInfo: jest.fn(async () => ({}))
}));

jest.mock('../../../../../../webapp/model/user.js', () => ({
    __esModule: true,
    default: {
        find: jest.fn(async () => mockState.userFindResult),
        findById: jest.fn(async () => mockState.userById),
        updateById: jest.fn(async () => ({})),
        create: jest.fn(async () => {
            if (mockState.createError) {
                const error = mockState.createError;
                mockState.createError = null;
                throw error;
            }
            return mockState.createdUser;
        }),
        getCollection: jest.fn()
    }
}));

jest.mock('../../../../../../webapp/model/plugin.js', () => ({
    __esModule: true,
    default: {
        getByName: jest.fn(async () => mockState.pluginDoc),
        upsert: jest.fn(async (name, configData) => {
            mockState.upsertedConfig = configData;
            return { _id: 'plugin-doc-id', name, modified: true };
        })
    }
}));

jest.mock('../../../../../../webapp/controller/auth.js', () => ({
    __esModule: true,
    default: { completeExternalAuth: jest.fn(async (req, res) => res.redirect('/')) }
}));

jest.mock('../../../../../../webapp/model/config.js', () => ({
    __esModule: true,
    default: {
        getEffectiveAdminRoles: jest.fn(() => mockState.adminRoles),
        getEffectiveRoles: jest.fn(() => mockState.siteRoles)
    }
}));

function makeReq({ params = {}, query = {}, session = {} } = {}) {
    return {
        params,
        query,
        session,
        protocol: 'https',
        headers: {},
        ip: '203.0.113.7',
        connection: { remoteAddress: '203.0.113.7' },
        get: jest.fn(() => 'app.example.com'),
        originalUrl: `/api/1/auth-oauth/callback/${params.provider || 'test'}${
            Object.keys(query).length ? '?' + new URLSearchParams(query).toString() : ''
        }`
    };
}

/** Same as makeReq(), but with an authenticated session.user (for the auth:'user' endpoints). */
function makeAuthedReq({ params = {}, query = {}, session = {}, userId = 'user-id-1', username = 'testuser' } = {}) {
    return makeReq({
        params,
        query,
        session: { user: { id: userId, username }, ...session }
    });
}

function makeRes() {
    return {
        redirect: jest.fn(),
        json: jest.fn(),
        status: jest.fn().mockReturnThis()
    };
}

describe('OauthAuthController', () => {
    let OauthAuthController, OauthProviderModel, OauthAuthModel, oauthClient, UserModel, PluginModel, AuthController;

    beforeAll(async () => {
        OauthProviderModel = (await import('../../../model/oauthProvider.js')).default;
        OauthAuthModel = (await import('../../../model/oauthAuth.js')).default;
        oauthClient = await import('../../../utils/oauthClient.js');
        UserModel = (await import('../../../../../../webapp/model/user.js')).default;
        PluginModel = (await import('../../../../../../webapp/model/plugin.js')).default;
        AuthController = (await import('../../../../../../webapp/controller/auth.js')).default;
        OauthAuthController = (await import('../../../controller/oauthAuth.js')).default;
    });

    beforeEach(() => {
        jest.clearAllMocks();

        global.LogController = {
            logRequest: jest.fn(),
            logInfo: jest.fn(),
            logError: jest.fn(),
            logWarning: jest.fn()
        };
        // sanitizeHtml is the real implementation (pure function) so icon-sanitization tests
        // exercise actual framework behavior, not a stub; sendError stays mocked for assertions.
        global.CommonUtils = { sendError: jest.fn(), sanitizeHtml: CommonUtils.sanitizeHtml };
        global.RedisManager = { cacheCheckRateLimit: jest.fn(async () => ({ allowed: true, count: 1, retryAfter: 0 })) };

        mockState.providers = [];
        mockState.providerWithSecret = null;
        mockState.userFindResult = [];
        mockState.pluginDoc = { config: { defaultLinkingStrategy: 'link-by-email' } };
        mockState.userById = null;
        mockState.linkedProviders = [];
        mockState.canUnlinkResult = { allowed: true };
        mockState.findUserByProviderSubResult = null;
        mockState.createdUser = null;
        mockState.createError = null;
        mockState.providerById = null;
        mockState.upsertedConfig = null;
        mockState.adminRoles = ['admin', 'root'];
        mockState.siteRoles = ['user', 'admin', 'root'];
    });

    describe('apiProviders', () => {
        test('lists enabled providers only, sorted by order, without secrets', async () => {
            mockState.providers = [
                { id: 'b-provider', label: 'B', icon: '🔗', buttonColor: '#111', enabled: true, order: 20 },
                { id: 'a-provider', label: 'A', icon: '🔐', buttonColor: '#222', enabled: true, order: 10 },
                { id: 'disabled-one', label: 'Disabled', enabled: false, order: 5 }
            ];
            const req = makeReq();
            const res = makeRes();

            await OauthAuthController.apiProviders(req, res);

            expect(res.json).toHaveBeenCalledWith({
                success: true,
                data: [
                    { id: 'a-provider', label: 'A', icon: '🔐', buttonColor: '#222', initUrl: '/api/1/auth-oauth/init/a-provider', order: 10 },
                    { id: 'b-provider', label: 'B', icon: '🔗', buttonColor: '#111', initUrl: '/api/1/auth-oauth/init/b-provider', order: 20 }
                ]
            });
        });

        test('falls back to the preset label/icon/color when the admin left them blank', async () => {
            mockState.providers = [
                { id: 'google-corp', preset: 'google', enabled: true, order: 0 }
            ];
            const req = makeReq();
            const res = makeRes();

            await OauthAuthController.apiProviders(req, res);

            expect(res.json).toHaveBeenCalledWith({
                success: true,
                data: [
                    { id: 'google-corp', label: 'Google', icon: getPreset('google').icon, buttonColor: '#4285F4',
                      initUrl: '/api/1/auth-oauth/init/google-corp', order: 0 }
                ]
            });
        });

        test('sends a 500 error when the provider list read fails', async () => {
            OauthProviderModel.getCachedProviders.mockRejectedValueOnce(new Error('boom'));
            const req = makeReq();
            const res = makeRes();

            await OauthAuthController.apiProviders(req, res);

            expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 500, expect.any(String), 'INTERNAL_ERROR');
        });

        test('reads through the §13 cache (getCachedProviders), not the uncached getProviders', async () => {
            mockState.providers = [{ id: 'a-provider', label: 'A', enabled: true, order: 10 }];
            const req = makeReq();
            const res = makeRes();

            await OauthAuthController.apiProviders(req, res);

            expect(OauthProviderModel.getCachedProviders).toHaveBeenCalled();
            expect(OauthProviderModel.getProviders).not.toHaveBeenCalled();
        });
    });

    describe('onAuthGetLoginProviders hook', () => {
        test('pushes enabled provider buttons into context.providers (§13 cached read)', async () => {
            mockState.providers = [
                { id: 'google-corp', label: 'Google', icon: '🇬', buttonColor: '#4285F4', enabled: true, order: 10 },
                { id: 'disabled-one', label: 'Disabled', enabled: false, order: 5 }
            ];
            const context = { req: makeReq(), providers: [] };

            const result = await OauthAuthController.onAuthGetLoginProviders(context);

            expect(OauthProviderModel.getCachedProviders).toHaveBeenCalled();
            expect(result.providers).toEqual([
                { id: 'google-corp', label: 'Google', icon: '🇬', buttonColor: '#4285F4', initUrl: '/api/1/auth-oauth/init/google-corp', order: 10 }
            ]);
        });

        test('does not throw and returns context unchanged when the cached read fails', async () => {
            OauthProviderModel.getCachedProviders.mockRejectedValueOnce(new Error('redis down'));
            const context = { req: makeReq(), providers: [] };

            const result = await OauthAuthController.onAuthGetLoginProviders(context);

            expect(result.providers).toEqual([]);
            expect(global.LogController.logWarning).toHaveBeenCalled();
        });
    });

    describe('apiInit', () => {
        test('redirects to the error page when rate limited', async () => {
            global.RedisManager.cacheCheckRateLimit.mockResolvedValueOnce({ allowed: false, count: 999, retryAfter: 30 });
            const req = makeReq({ params: { provider: 'google-corp' } });
            const res = makeRes();

            await OauthAuthController.apiInit(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=RATE_LIMITED');
        });

        test('redirects to the error page for an unknown provider', async () => {
            mockState.providerWithSecret = null;
            const req = makeReq({ params: { provider: 'does-not-exist' } });
            const res = makeRes();

            await OauthAuthController.apiInit(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=PROVIDER_ERROR');
        });

        test('redirects to the error page for a disabled provider', async () => {
            mockState.providerWithSecret = { id: 'google-corp', type: 'oidc', enabled: false, scopes: ['openid'] };
            const req = makeReq({ params: { provider: 'google-corp' } });
            const res = makeRes();

            await OauthAuthController.apiInit(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=PROVIDER_ERROR');
        });

        test('generates PKCE + state + nonce for an OIDC provider, stores pending, and redirects to the authorization URL', async () => {
            mockState.providerWithSecret = { id: 'google-corp', type: 'oidc', enabled: true, scopes: ['openid', 'email'] };
            const req = makeReq({ params: { provider: 'google-corp' }, query: { redirect: '/dashboard' } });
            const res = makeRes();

            await OauthAuthController.apiInit(req, res);

            expect(req.session.oauthPending).toMatchObject({
                provider: 'google-corp',
                mode: 'login',
                state: 'test-state',
                nonce: 'test-nonce',
                codeVerifier: 'test-code-verifier',
                redirectUrl: '/dashboard'
            });
            expect(oauthClient.buildAuthorizationUrl).toHaveBeenCalledWith(
                expect.objectContaining({ __fakeConfig: true }),
                expect.objectContaining({
                    redirectUri: 'https://app.example.com/api/1/auth-oauth/callback/google-corp',
                    scopes: ['openid', 'email'],
                    state: 'test-state',
                    codeChallenge: 'test-code-challenge',
                    nonce: 'test-nonce'
                })
            );
            expect(res.redirect).toHaveBeenCalledWith('https://idp.example.com/authorize?state=test-state');
        });

        test('omits the nonce for a non-OIDC (custom OAuth2) provider', async () => {
            mockState.providerWithSecret = { id: 'legacy-sso', type: 'oauth2', enabled: true, scopes: [] };
            const req = makeReq({ params: { provider: 'legacy-sso' } });
            const res = makeRes();

            await OauthAuthController.apiInit(req, res);

            expect(req.session.oauthPending.nonce).toBeNull();
            expect(oauthClient.generateNonce).not.toHaveBeenCalled();
        });

        test('redirects to the error page when the default redirect (no ?redirect=) is used', async () => {
            mockState.providerWithSecret = { id: 'google-corp', type: 'oidc', enabled: true, scopes: ['openid'] };
            const req = makeReq({ params: { provider: 'google-corp' } });
            const res = makeRes();

            await OauthAuthController.apiInit(req, res);

            expect(req.session.oauthPending.redirectUrl).toBe('/');
        });
    });

    describe('apiCallback', () => {
        const oidcProvider = { id: 'google-corp', type: 'oidc', enabled: true, scopes: ['openid', 'email'] };

        function makePendingReq(overrides = {}) {
            return makeReq({
                params: { provider: 'google-corp' },
                query: { code: 'test-code', state: 'test-state' },
                session: {
                    oauthPending: {
                        provider: 'google-corp',
                        mode: 'login',
                        state: 'test-state',
                        nonce: 'test-nonce',
                        codeVerifier: 'test-code-verifier',
                        redirectUrl: '/dashboard',
                        createdAt: Date.now()
                    }
                },
                ...overrides
            });
        }

        test('redirects to the error page when rate limited', async () => {
            global.RedisManager.cacheCheckRateLimit.mockResolvedValueOnce({ allowed: false, count: 999, retryAfter: 30 });
            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=RATE_LIMITED');
        });

        test('redirects to the error page when the provider returned an error', async () => {
            const req = makePendingReq({ query: { error: 'access_denied' } });
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=PROVIDER_ERROR');
            expect(req.session.oauthPending).toBeUndefined();
        });

        test('redirects to the error page when there is no pending session', async () => {
            const req = makeReq({ params: { provider: 'google-corp' }, query: { code: 'test-code', state: 'test-state' } });
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=STATE_MISMATCH');
        });

        test('redirects to the error page when the pending session is for a different provider', async () => {
            const req = makePendingReq({ params: { provider: 'okta-prod' } });
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=STATE_MISMATCH');
        });

        test('redirects to the error page when the pending session has expired (> 5 minutes)', async () => {
            const req = makePendingReq();
            req.session.oauthPending.createdAt = Date.now() - (6 * 60 * 1000);
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=STATE_MISMATCH');
        });

        test('redirects to the error page when the provider is no longer configured/enabled', async () => {
            mockState.providerWithSecret = null;
            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=PROVIDER_ERROR');
        });

        test('sub-only fast path: resolves an existing linked user and hands off to completeExternalAuth', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-123', email: 'user@example.com', email_verified: true, name: 'Test User' }
            });
            const existingUser = { _id: 'user-id-1', username: 'testuser', status: 'active', oauth: { 'google-corp': { sub: 'sub-123' } } };
            mockState.userFindResult = [existingUser];

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(UserModel.find).toHaveBeenCalledWith({ 'oauth.google-corp.sub': 'sub-123' }, { limit: 1 });
            expect(UserModel.updateById).toHaveBeenCalledWith('user-id-1', expect.objectContaining({
                'oauth.google-corp': expect.objectContaining({ sub: 'sub-123', email: 'user@example.com' })
            }));
            expect(AuthController.completeExternalAuth).toHaveBeenCalledWith(req, res, existingUser, 'oauth', '/dashboard');
            expect(req.session.oauthPending).toBeUndefined();
        });

        test('link-by-email: links a single matching existing user on first SSO login', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-456', email: 'user@example.com', email_verified: true, name: 'Test User' }
            });
            const existingUser = { _id: 'user-id-2', username: 'existinguser', status: 'active', email: 'user@example.com' };
            UserModel.find
                .mockResolvedValueOnce([]) // sub lookup: no match
                .mockResolvedValueOnce([existingUser]); // email lookup: single match

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(UserModel.find).toHaveBeenNthCalledWith(2, { email: 'user@example.com' }, { limit: 2 });
            expect(AuthController.completeExternalAuth).toHaveBeenCalledWith(req, res, existingUser, 'oauth', '/dashboard');
        });

        test('link-by-email: rejects an unverified email at the provider', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-789', email: 'user@example.com', email_verified: false }
            });

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=EMAIL_NOT_VERIFIED_AT_PROVIDER');
            expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
        });

        test('link-by-email: rejects when the email matches more than one local account', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-999', email: 'shared@example.com', email_verified: true }
            });
            UserModel.find
                .mockResolvedValueOnce([])
                .mockResolvedValueOnce([{ _id: 'a' }, { _id: 'b' }]);

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=AMBIGUOUS_EMAIL_MATCH');
        });

        test('link-by-email: normalizes a mixed-case IdP email before the local lookup (W-198)', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-456', email: 'User@Example.COM', email_verified: true, name: 'Test User' }
            });
            const existingUser = { _id: 'user-id-2', username: 'existinguser', status: 'active', email: 'user@example.com' };
            UserModel.find
                .mockResolvedValueOnce([])
                .mockResolvedValueOnce([existingUser]);

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(UserModel.find).toHaveBeenNthCalledWith(2, { email: 'user@example.com' }, { limit: 2 });
            expect(AuthController.completeExternalAuth).toHaveBeenCalledWith(req, res, existingUser, 'oauth', '/dashboard');
        });

        test('link-by-email: fails closed with LOCAL_EMAIL_NOT_VERIFIED when the matched local account has not verified its email (W-198)', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-456', email: 'squatted@example.com', email_verified: true, name: 'Test User' }
            });
            const unverifiedLocalUser = {
                _id: 'user-id-attacker', username: 'attacker', status: 'active',
                email: 'squatted@example.com', emailVerified: false
            };
            UserModel.find
                .mockResolvedValueOnce([])
                .mockResolvedValueOnce([unverifiedLocalUser]);

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=LOCAL_EMAIL_NOT_VERIFIED');
            expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
        });

        test('link-by-email: links a matched account whose emailVerified is missing (pre-W-198, grandfathered)', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-456', email: 'user@example.com', email_verified: true, name: 'Test User' }
            });
            const existingUser = { _id: 'user-id-2', username: 'existinguser', status: 'active', email: 'user@example.com' };
            UserModel.find
                .mockResolvedValueOnce([])
                .mockResolvedValueOnce([existingUser]);

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(AuthController.completeExternalAuth).toHaveBeenCalledWith(req, res, existingUser, 'oauth', '/dashboard');
        });

        test('sub-only/link-by-email: rejects with USER_NOT_PROVISIONED when no sub or email match is found', async () => {
            mockState.providerWithSecret = oidcProvider;
            mockState.pluginDoc = { config: { defaultLinkingStrategy: 'link-by-email' } };
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-new', email: 'newuser@example.com', email_verified: true }
            });

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=USER_NOT_PROVISIONED');
        });

        describe('jit-create', () => {
            test('creates a new user with a clean extraction (no profile-complete step needed) and logs in', async () => {
                mockState.providerWithSecret = { ...oidcProvider, linkingStrategy: 'jit-create' };
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: {
                        sub: 'sub-new', email: 'jane@example.com', email_verified: true,
                        name: 'Jane Doe', given_name: 'Jane', family_name: 'Doe'
                    }
                });
                const newUser = {
                    _id: 'user-id-new', username: 'jane', status: 'active',
                    profile: { firstName: 'Jane', lastName: 'Doe' },
                    oauth: { _jit: { createdAt: new Date(), viaProvider: 'google-corp', placeholderFields: [], profileCompletedAt: null } }
                };
                mockState.createdUser = newUser;

                const req = makePendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(UserModel.create).toHaveBeenCalledWith(expect.objectContaining({
                    username: 'jane',
                    email: 'jane@example.com',
                    emailVerified: true,
                    hasLocalPassword: false,
                    roles: ['user'],
                    status: 'active',
                    profile: expect.objectContaining({ firstName: 'Jane', lastName: 'Doe' }),
                    oauth: { _jit: expect.objectContaining({ viaProvider: 'google-corp', placeholderFields: [] }) }
                }));
                expect(AuthController.completeExternalAuth).toHaveBeenCalledWith(req, res, newUser, 'oauth', '/dashboard');
            });

            test('creates a placeholder profile when the IdP provides no name claims, and appends -N on username collision', async () => {
                mockState.providerWithSecret = { ...oidcProvider, linkingStrategy: 'jit-create' };
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-new', email: 'jane@example.com', email_verified: true }
                });
                const createError = new Error('Failed to create user: Username already exists');
                mockState.createError = createError;
                mockState.createdUser = { _id: 'user-id-new', username: 'jane-2', status: 'active' };

                const req = makePendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(UserModel.create).toHaveBeenNthCalledWith(1, expect.objectContaining({ username: 'jane' }));
                expect(UserModel.create).toHaveBeenNthCalledWith(2, expect.objectContaining({
                    username: 'jane-2',
                    oauth: { _jit: expect.objectContaining({ placeholderFields: ['firstName', 'lastName'] }) }
                }));
                expect(AuthController.completeExternalAuth).toHaveBeenCalled();
            });

            test('falls back to a sub/email lookup when a concurrent jit-create race loses the duplicate-key error', async () => {
                mockState.providerWithSecret = { ...oidcProvider, linkingStrategy: 'jit-create' };
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-race', email: 'race@example.com', email_verified: true, name: 'Race User' }
                });
                mockState.createError = new Error('Failed to create user: E11000 duplicate key error');
                const racedWinner = { _id: 'user-id-race', username: 'racewinner', status: 'active', email: 'race@example.com' };
                // sub lookup -> [], email lookup -> [], then the post-race lookup -> [racedWinner]
                UserModel.find
                    .mockResolvedValueOnce([])
                    .mockResolvedValueOnce([])
                    .mockResolvedValueOnce([racedWinner]);

                const req = makePendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(AuthController.completeExternalAuth).toHaveBeenCalledWith(req, res, racedWinner, 'oauth', '/dashboard');
            });

            test('strips admin/root from jitDefaultRoles (defense in depth)', async () => {
                mockState.providerWithSecret = { ...oidcProvider, linkingStrategy: 'jit-create' };
                mockState.pluginDoc = { config: { jitDefaultRoles: ['user', 'admin', 'root'] } };
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-new', email: 'jane@example.com', email_verified: true, name: 'Jane Doe' }
                });
                mockState.createdUser = { _id: 'user-id-new', username: 'jane', status: 'active' };

                const req = makePendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(UserModel.create).toHaveBeenCalledWith(expect.objectContaining({ roles: ['user'] }));
            });

            test('strips a site-defined admin-equivalent role, not just the literal admin/root (W-147)', async () => {
                // A site can add a custom role (e.g. "superuser") to data.general.adminRoles;
                // sanitizeJitRoles() must consult that, not a hardcoded ['admin', 'root'] list.
                mockState.adminRoles = ['admin', 'root', 'superuser'];
                mockState.providerWithSecret = { ...oidcProvider, linkingStrategy: 'jit-create' };
                mockState.pluginDoc = { config: { jitDefaultRoles: ['user', 'superuser'] } };
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-new', email: 'jane@example.com', email_verified: true, name: 'Jane Doe' }
                });
                mockState.createdUser = { _id: 'user-id-new', username: 'jane', status: 'active' };

                const req = makePendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(UserModel.create).toHaveBeenCalledWith(expect.objectContaining({ roles: ['user'] }));
            });

            test('redirects to ACCOUNT_PENDING_APPROVAL when jitDefaultStatus is pending', async () => {
                mockState.providerWithSecret = { ...oidcProvider, linkingStrategy: 'jit-create' };
                mockState.pluginDoc = { config: { jitDefaultStatus: 'pending' } };
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-new', email: 'jane@example.com', email_verified: true, name: 'Jane Doe' }
                });
                mockState.createdUser = { _id: 'user-id-new', username: 'jane', status: 'pending' };

                const req = makePendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(UserModel.create).toHaveBeenCalledWith(expect.objectContaining({ status: 'pending' }));
                expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=ACCOUNT_PENDING_APPROVAL');
                expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
            });
        });

        test('rejects a suspended account', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-123', email: 'user@example.com', email_verified: true }
            });
            mockState.userFindResult = [{ _id: 'user-id-3', username: 'suspendeduser', status: 'suspended' }];

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=ACCOUNT_SUSPENDED');
            expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
        });

        test('rejects a terminated account', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-123', email: 'user@example.com', email_verified: true }
            });
            mockState.userFindResult = [{ _id: 'user-id-4', username: 'terminateduser', status: 'terminated' }];

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=ACCOUNT_TERMINATED');
            expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
        });

        test('rejects an inactive account', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-123', email: 'user@example.com', email_verified: true }
            });
            mockState.userFindResult = [{ _id: 'user-id-6', username: 'inactiveuser', status: 'inactive' }];

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=ACCOUNT_INACTIVE');
            expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
        });

        test('allowedDomains rejects an existing sub-matched user whose identity email domain is no longer allowed', async () => {
            mockState.providerWithSecret = { ...oidcProvider, allowedDomains: ['corp.example.com'] };
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-123', email: 'user@gmail.com', email_verified: true }
            });
            // Sub-match lookup succeeds (this user was already linked before allowedDomains was tightened)
            mockState.userFindResult = [{ _id: 'user-id-7', username: 'existinguser', status: 'active' }];

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=DOMAIN_NOT_ALLOWED');
            expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
        });

        test('allowedDomains rejects a jit-create attempt from a disallowed domain before any user is created', async () => {
            mockState.providerWithSecret = { ...oidcProvider, linkingStrategy: 'jit-create', allowedDomains: ['corp.example.com'] };
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-new', email: 'jane@gmail.com', email_verified: true, name: 'Jane Doe' }
            });

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=DOMAIN_NOT_ALLOWED');
            expect(UserModel.create).not.toHaveBeenCalled();
            expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
        });

        test('allowedDomains allows a jit-create attempt whose identity email domain matches the allowlist', async () => {
            mockState.providerWithSecret = { ...oidcProvider, linkingStrategy: 'jit-create', allowedDomains: ['corp.example.com'] };
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: { sub: 'sub-new', email: 'jane@corp.example.com', email_verified: true, name: 'Jane Doe' }
            });
            mockState.createdUser = { _id: 'user-id-new', username: 'jane', status: 'active' };

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(AuthController.completeExternalAuth).toHaveBeenCalled();
        });

        test('custom OAuth2 preset: fetches userinfo and maps fields per the admin-configured mapping', async () => {
            mockState.providerWithSecret = {
                id: 'legacy-sso', type: 'oauth2', enabled: true, scopes: [],
                userinfoMapping: { sub: 'id', email: 'mail', name: 'displayName' }
            };
            oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                tokens: { access_token: 'test-access-token' },
                claims: undefined
            });
            oauthClient.fetchUserInfo.mockResolvedValueOnce({ id: 'ext-42', mail: 'ext@example.com', displayName: 'Ext User' });
            const existingUser = { _id: 'user-id-5', username: 'extuser', status: 'active', oauth: { 'legacy-sso': { sub: 'ext-42' } } };
            mockState.userFindResult = [existingUser];

            const req = makePendingReq({ params: { provider: 'legacy-sso' }, session: {
                oauthPending: {
                    provider: 'legacy-sso', mode: 'login', state: 'test-state', nonce: null,
                    codeVerifier: 'test-code-verifier', redirectUrl: '/dashboard', createdAt: Date.now()
                }
            } });
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(oauthClient.fetchUserInfo).toHaveBeenCalledWith(expect.objectContaining({ __fakeConfig: true }), 'test-access-token');
            expect(UserModel.find).toHaveBeenCalledWith({ 'oauth.legacy-sso.sub': 'ext-42' }, { limit: 1 });
            expect(AuthController.completeExternalAuth).toHaveBeenCalledWith(req, res, existingUser, 'oauth', '/dashboard');
        });

        test('redirects to the error page and clears pending state on an unexpected exception (e.g. token exchange failure)', async () => {
            mockState.providerWithSecret = oidcProvider;
            oauthClient.exchangeCodeForTokens.mockRejectedValueOnce(new Error('state mismatch from library'));

            const req = makePendingReq();
            const res = makeRes();

            await OauthAuthController.apiCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=INTERNAL_ERROR');
            expect(req.session.oauthPending).toBeUndefined();
        });

        describe("'link' mode (apiLink-initiated)", () => {
            function makeLinkPendingReq(overrides = {}) {
                return makeAuthedReq({
                    params: { provider: 'google-corp' },
                    query: { code: 'test-code', state: 'test-state' },
                    userId: 'user-id-1',
                    username: 'testuser',
                    session: {
                        oauthPending: {
                            provider: 'google-corp',
                            mode: 'link',
                            userId: 'user-id-1',
                            state: 'test-state',
                            nonce: 'test-nonce',
                            codeVerifier: 'test-code-verifier',
                            redirectUrl: '/jpulse-plugins/auth-oauth.shtml',
                            createdAt: Date.now()
                        }
                    },
                    ...overrides
                });
            }

            test('links the identity to the already-authenticated user and redirects with ?linked=1', async () => {
                mockState.providerWithSecret = oidcProvider;
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-123', email: 'user@example.com', email_verified: true }
                });
                mockState.findUserByProviderSubResult = null; // not linked to anyone yet
                mockState.userById = { _id: 'user-id-1', username: 'testuser', oauth: {} };

                const req = makeLinkPendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(UserModel.updateById).toHaveBeenCalledWith('user-id-1', expect.objectContaining({
                    'oauth.google-corp': expect.objectContaining({ sub: 'sub-123' })
                }));
                expect(res.redirect).toHaveBeenCalledWith('/jpulse-plugins/auth-oauth.shtml?linked=1');
                expect(AuthController.completeExternalAuth).not.toHaveBeenCalled();
            });

            test('rejects when the session user no longer matches the user who started the link flow', async () => {
                mockState.providerWithSecret = oidcProvider;
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-123', email: 'user@example.com', email_verified: true }
                });

                const req = makeLinkPendingReq({ userId: 'a-different-user-id' });
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=STATE_MISMATCH');
            });

            test('rejects when the sub is already linked to a different account', async () => {
                mockState.providerWithSecret = oidcProvider;
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-123', email: 'user@example.com', email_verified: true }
                });
                mockState.findUserByProviderSubResult = { _id: { toString: () => 'some-other-user-id' } };

                const req = makeLinkPendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(res.redirect).toHaveBeenCalledWith('/auth/oauth-error.shtml?reason=ALREADY_LINKED_TO_ANOTHER_ACCOUNT');
                expect(UserModel.updateById).not.toHaveBeenCalled();
            });

            test('allows re-linking a sub already linked to the same account (no-op re-auth)', async () => {
                mockState.providerWithSecret = oidcProvider;
                oauthClient.exchangeCodeForTokens.mockResolvedValueOnce({
                    tokens: { access_token: 'test-access-token' },
                    claims: { sub: 'sub-123', email: 'user@example.com', email_verified: true }
                });
                mockState.findUserByProviderSubResult = { _id: { toString: () => 'user-id-1' } };
                mockState.userById = { _id: 'user-id-1', username: 'testuser', oauth: { 'google-corp': { sub: 'sub-123' } } };

                const req = makeLinkPendingReq();
                const res = makeRes();

                await OauthAuthController.apiCallback(req, res);

                expect(res.redirect).toHaveBeenCalledWith('/jpulse-plugins/auth-oauth.shtml?linked=1');
            });
        });
    });

    describe('apiUserProviders', () => {
        test("lists the user's linked providers plus still-available enabled providers", async () => {
            mockState.userById = { _id: 'user-id-1', username: 'testuser', hasLocalPassword: true, oauth: { 'google-corp': {} } };
            mockState.linkedProviders = [{ providerId: 'google-corp', sub: 'sub-123', email: 'user@example.com', linkedAt: 'then', lastLoginAt: 'now' }];
            mockState.canUnlinkResult = { allowed: true };
            mockState.providers = [
                { id: 'google-corp', label: 'Google', icon: '🇬', enabled: true },
                { id: 'okta-prod', label: 'Okta', icon: '🔐', enabled: true }
            ];

            const req = makeAuthedReq();
            const res = makeRes();

            await OauthAuthController.apiUserProviders(req, res);

            expect(res.json).toHaveBeenCalledWith({
                success: true,
                data: {
                    linked: [{
                        providerId: 'google-corp', label: 'Google', icon: '🇬', email: 'user@example.com',
                        linkedAt: 'then', lastLoginAt: 'now', canUnlink: true, unlinkBlockedReason: null
                    }],
                    available: [{ providerId: 'okta-prod', label: 'Okta', icon: '🔐', linkUrl: '/api/1/auth-oauth/link/okta-prod' }],
                    hasLocalPassword: true
                }
            });
        });

        test('inherits the preset label/icon for blank fields, same as the login page', async () => {
            mockState.userById = { _id: 'user-id-1', username: 'testuser', hasLocalPassword: true, oauth: { 'google-corp': {} } };
            mockState.linkedProviders = [{ providerId: 'google-corp', sub: 'sub-123', email: 'user@example.com' }];
            mockState.canUnlinkResult = { allowed: true };
            mockState.providers = [
                { id: 'google-corp', preset: 'google', enabled: true },
                { id: 'okta-prod', preset: 'oidc', enabled: true }
            ];

            const req = makeAuthedReq();
            const res = makeRes();

            await OauthAuthController.apiUserProviders(req, res);

            const { linked, available } = res.json.mock.calls[0][0].data;
            expect(linked[0]).toMatchObject({ label: 'Google', icon: getPreset('google').icon });
            expect(available[0]).toMatchObject({ label: 'OIDC Provider', icon: '🔐' });
        });

        test('sends a 404 when the user cannot be found', async () => {
            mockState.userById = null;
            const req = makeAuthedReq();
            const res = makeRes();

            await OauthAuthController.apiUserProviders(req, res);

            expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 404, 'User not found', 'NOT_FOUND');
        });
    });

    describe('apiLink', () => {
        test('starts a link flow and returns the authorization redirectUrl as JSON', async () => {
            mockState.providerWithSecret = { id: 'google-corp', type: 'oidc', enabled: true, scopes: ['openid'] };
            const req = makeAuthedReq({ params: { provider: 'google-corp' } });
            const res = makeRes();

            await OauthAuthController.apiLink(req, res);

            expect(req.session.oauthPending).toMatchObject({
                provider: 'google-corp',
                mode: 'link',
                userId: 'user-id-1',
                redirectUrl: '/jpulse-plugins/auth-oauth.shtml'
            });
            expect(res.json).toHaveBeenCalledWith({ success: true, data: { redirectUrl: 'https://idp.example.com/authorize?state=test-state' } });
        });

        test('sends a 404 for an unknown or disabled provider', async () => {
            mockState.providerWithSecret = null;
            const req = makeAuthedReq({ params: { provider: 'does-not-exist' } });
            const res = makeRes();

            await OauthAuthController.apiLink(req, res);

            expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 404, 'Provider not found or disabled', 'PROVIDER_ERROR');
        });
    });

    describe('apiUnlink', () => {
        test('unlinks an allowed provider', async () => {
            mockState.userById = { _id: 'user-id-1', username: 'testuser', oauth: { 'google-corp': {} } };
            mockState.canUnlinkResult = { allowed: true };
            const req = makeAuthedReq({ params: { provider: 'google-corp' } });
            const res = makeRes();

            await OauthAuthController.apiUnlink(req, res);

            expect(OauthAuthModel.unlinkProvider).toHaveBeenCalledWith('user-id-1', 'google-corp');
            expect(res.json).toHaveBeenCalledWith({ success: true });
        });

        test('blocks unlinking the last sign-in method when the user has no local password', async () => {
            mockState.userById = { _id: 'user-id-1', username: 'testuser', oauth: { 'google-corp': {} } };
            mockState.canUnlinkResult = { allowed: false, reason: 'LAST_SIGNIN_METHOD' };
            const req = makeAuthedReq({ params: { provider: 'google-corp' } });
            const res = makeRes();

            await OauthAuthController.apiUnlink(req, res);

            expect(OauthAuthModel.unlinkProvider).not.toHaveBeenCalled();
            expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'LAST_SIGNIN_METHOD');
        });

        test('sends a 404 when the user cannot be found', async () => {
            mockState.userById = null;
            const req = makeAuthedReq({ params: { provider: 'google-corp' } });
            const res = makeRes();

            await OauthAuthController.apiUnlink(req, res);

            expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 404, 'User not found', 'NOT_FOUND');
        });
    });

    describe('onAuthGetSteps hook (jit-create Stage B)', () => {
        test('injects the oauth-profile-complete step when placeholder fields are still required', async () => {
            mockState.pluginDoc = { config: { profileRequiredFields: ['firstName', 'lastName'] } };
            const user = {
                profile: { firstName: 'jane', lastName: '-' },
                oauth: { _jit: { placeholderFields: ['lastName'], profileCompletedAt: null } }
            };
            const context = { req: makeReq(), user, completedSteps: [], requiredSteps: [] };

            const result = await OauthAuthController.onAuthGetSteps(context);

            expect(result.requiredSteps).toEqual([expect.objectContaining({
                step: 'oauth-profile-complete',
                page: '/auth/oauth-profile-complete.shtml',
                data: expect.objectContaining({ missingFields: ['lastName'] })
            })]);
        });

        test('does nothing for a user with no oauth._jit sentinel (not jit-created)', async () => {
            const context = { req: makeReq(), user: { profile: {} }, completedSteps: [], requiredSteps: [] };

            const result = await OauthAuthController.onAuthGetSteps(context);

            expect(result.requiredSteps).toEqual([]);
        });

        test('does nothing once profileCompletedAt is set', async () => {
            const user = { oauth: { _jit: { placeholderFields: ['lastName'], profileCompletedAt: new Date() } } };
            const context = { req: makeReq(), user, completedSteps: [], requiredSteps: [] };

            const result = await OauthAuthController.onAuthGetSteps(context);

            expect(result.requiredSteps).toEqual([]);
        });

        test('does nothing when placeholder fields are outside profileRequiredFields', async () => {
            mockState.pluginDoc = { config: { profileRequiredFields: [] } };
            const user = { oauth: { _jit: { placeholderFields: ['lastName'], profileCompletedAt: null } } };
            const context = { req: makeReq(), user, completedSteps: [], requiredSteps: [] };

            const result = await OauthAuthController.onAuthGetSteps(context);

            expect(result.requiredSteps).toEqual([]);
        });
    });

    describe('onAuthValidateStep hook (jit-create Stage B)', () => {
        test('saves submitted fields and clears the placeholder sentinel', async () => {
            const user = { _id: 'user-id-new', username: 'jane' };
            const context = {
                req: makeReq(), step: 'oauth-profile-complete',
                stepData: { firstName: 'Jane', lastName: 'Doe', nickName: '' },
                user, valid: false, error: null
            };

            const result = await OauthAuthController.onAuthValidateStep(context);

            expect(result.valid).toBe(true);
            expect(UserModel.updateById).toHaveBeenCalledWith('user-id-new', expect.objectContaining({
                'profile.firstName': 'Jane',
                'profile.lastName': 'Doe',
                'oauth._jit.placeholderFields': [],
                'oauth._jit.profileCompletedAt': expect.any(Date)
            }));
        });

        test('ignores unrelated steps', async () => {
            const context = { req: makeReq(), step: 'mfa', stepData: {}, user: {}, valid: false, error: null };

            const result = await OauthAuthController.onAuthValidateStep(context);

            expect(result.valid).toBe(false);
            expect(UserModel.updateById).not.toHaveBeenCalled();
        });

        test('fails validation when a required field is blank', async () => {
            mockState.pluginDoc = { config: { profileRequiredFields: ['firstName', 'lastName'] } };
            const context = {
                req: makeReq(), step: 'oauth-profile-complete',
                stepData: { firstName: '', lastName: 'Doe' },
                user: { _id: 'user-id-new' }, valid: false, error: null
            };

            const result = await OauthAuthController.onAuthValidateStep(context);

            expect(result.valid).toBe(false);
            expect(result.error).toBeTruthy();
            expect(UserModel.updateById).not.toHaveBeenCalled();
        });
    });

    describe('apiProfileDraft', () => {
        function makePendingAuthReq() {
            return makeReq({
                session: {
                    pendingAuth: {
                        userId: 'user-id-new',
                        requiredSteps: ['credentials', 'oauth-profile-complete'],
                        completedSteps: ['credentials'],
                        createdAt: Date.now()
                    }
                }
            });
        }

        test('returns missingFields + current profile values for a pending jit-create user', async () => {
            mockState.pluginDoc = { config: { profileRequiredFields: ['firstName', 'lastName'] } };
            mockState.userById = {
                email: 'jane@example.com',
                profile: { firstName: 'jane', lastName: '-', nickName: '' },
                oauth: { _jit: { placeholderFields: ['lastName'], profileCompletedAt: null } }
            };

            const req = makePendingAuthReq();
            const res = makeRes();

            await OauthAuthController.apiProfileDraft(req, res);

            expect(res.json).toHaveBeenCalledWith({
                success: true,
                data: { email: 'jane@example.com', missingFields: ['lastName'], firstName: 'jane', lastName: '-', nickName: '' }
            });
        });

        test('sends STATE_MISMATCH when there is no pendingAuth session', async () => {
            const req = makeReq();
            const res = makeRes();

            await OauthAuthController.apiProfileDraft(req, res);

            expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'STATE_MISMATCH');
        });

        test('sends STATE_MISMATCH when the step is already completed', async () => {
            const req = makePendingAuthReq();
            req.session.pendingAuth.completedSteps.push('oauth-profile-complete');
            const res = makeRes();

            await OauthAuthController.apiProfileDraft(req, res);

            expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'STATE_MISMATCH');
        });

        test('sends STATE_MISMATCH when the user has no pending oauth._jit sentinel', async () => {
            mockState.userById = { email: 'jane@example.com', profile: {}, oauth: {} };
            const req = makePendingAuthReq();
            const res = makeRes();

            await OauthAuthController.apiProfileDraft(req, res);

            expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'STATE_MISMATCH');
        });
    });

    describe('admin provider CRUD/test endpoints (W-194 custom renderer backend)', () => {
        beforeEach(() => {
            mockState.pluginDoc = { config: { defaultLinkingStrategy: 'link-by-email', providers: [] } };
        });

        describe('apiAdminProviders', () => {
            test('lists all configured providers (raw config, no secrets requested)', async () => {
                mockState.providers = [{ id: 'google-corp', preset: 'google', enabled: true }];
                const req = makeAuthedReq();
                const res = makeRes();

                await OauthAuthController.apiAdminProviders(req, res);

                expect(res.json).toHaveBeenCalledWith({ success: true, data: mockState.providers });
            });
        });

        describe('apiAdminAssignableRoles', () => {
            test('returns this site\'s roles with admin-equivalent roles removed', async () => {
                mockState.siteRoles = ['user', 'admin', 'root', 'editor'];
                mockState.adminRoles = ['admin', 'root'];
                const req = makeAuthedReq();
                const res = makeRes();

                await OauthAuthController.apiAdminAssignableRoles(req, res);

                expect(res.json).toHaveBeenCalledWith({ success: true, data: { roles: ['user', 'editor'] } });
            });

            test('excludes a site-defined admin-equivalent role, not just the literal admin/root', async () => {
                mockState.siteRoles = ['user', 'admin', 'root', 'superuser'];
                mockState.adminRoles = ['admin', 'root', 'superuser'];
                const req = makeAuthedReq();
                const res = makeRes();

                await OauthAuthController.apiAdminAssignableRoles(req, res);

                expect(res.json).toHaveBeenCalledWith({ success: true, data: { roles: ['user'] } });
            });
        });

        describe('apiAdminProvidersCreate', () => {
            test('creates a provider, encrypts a submitted clientSecret, and saves the full config', async () => {
                mockState.pluginDoc = { config: { defaultLinkingStrategy: 'link-by-email', providers: [{ id: 'existing-one', preset: 'google' }] } };
                mockState.providerById = null;
                const req = makeAuthedReq({ params: {} });
                req.body = { id: 'google-corp', preset: 'google', label: 'Google', enabled: true, clientId: 'abc', clientSecret: 'shh' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(OauthProviderModel.setClientSecret).toHaveBeenCalledWith('google-corp', 'shh');
                expect(PluginModel.upsert).toHaveBeenCalledWith('auth-oauth', expect.objectContaining({
                    providers: [
                        { id: 'existing-one', preset: 'google' },
                        expect.objectContaining({ id: 'google-corp', clientSecretRef: 'ref:authOauth_providers/google-corp/clientSecret' })
                    ]
                }), 'testuser');
                expect(OauthProviderModel.invalidateCachedProviders).toHaveBeenCalled();
                expect(res.json).toHaveBeenCalledWith({ success: true, data: expect.objectContaining({ id: 'google-corp' }) });
                // Plaintext secret must never be persisted or echoed back
                const saved = mockState.upsertedConfig.providers.find(p => p.id === 'google-corp');
                expect(saved.clientSecret).toBeUndefined();
            });

            test('rejects an invalid provider id', async () => {
                const req = makeAuthedReq();
                req.body = { id: 'bad id!', preset: 'google' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('rejects an unknown preset', async () => {
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'not-a-real-preset' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
            });

            test('rejects a duplicate provider id', async () => {
                mockState.providerById = { id: 'google-corp', preset: 'google' };
                const req = makeAuthedReq();
                req.body = { id: 'google-corp', preset: 'google' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('rejects a non-hex buttonColor', async () => {
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'google', buttonColor: 'red' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('rejects a buttonColor value that would break out of the style attribute', async () => {
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'google', buttonColor: 'red;"><script>alert(1)</script>' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('accepts a valid 6-digit hex buttonColor', async () => {
                mockState.pluginDoc = { config: { providers: [] } };
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'google', buttonColor: '#4285F4' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).not.toHaveBeenCalled();
                expect(mockState.upsertedConfig.providers[0]).toEqual(expect.objectContaining({ buttonColor: '#4285F4' }));
            });

            test('rejects a label containing "<" or ">"', async () => {
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'google', label: '<script>alert(1)</script>' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('passes plain-text/emoji icon through unchanged', async () => {
                mockState.pluginDoc = { config: { providers: [] } };
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'oidc', icon: '🔐' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(mockState.upsertedConfig.providers[0]).toEqual(expect.objectContaining({ icon: '🔐' }));
            });

            test('sanitizes an icon containing markup, stripping a <script> payload', async () => {
                mockState.pluginDoc = { config: { providers: [] } };
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'oidc', icon: '<svg><script>alert(1)</script><path d="M1 1"></path></svg>' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                const saved = mockState.upsertedConfig.providers[0];
                expect(saved.icon).not.toContain('script');
                expect(saved.icon).toContain('<path');
            });

            test('preserves a safe single-color SVG icon, including hyphenated attributes', async () => {
                mockState.pluginDoc = { config: { providers: [] } };
                const req = makeAuthedReq();
                const svg = '<svg viewBox="0 0 24 24"><path d="M1 1h2v2H1z" stroke-width="2" fill="currentColor"></path></svg>';
                req.body = { id: 'my-provider', preset: 'oidc', icon: svg };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                const saved = mockState.upsertedConfig.providers[0];
                expect(saved.icon).toContain('<path');
                expect(saved.icon).toContain('stroke-width="2"');
                expect(saved.icon).toContain('fill="currentColor"');
            });

            test('rejects an allowedDomains entry that is not a plausible domain', async () => {
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'google', allowedDomains: ['not an email domain'] };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('rejects an allowedDomains entry containing "@" (email, not a domain)', async () => {
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'google', allowedDomains: ['user@corp.example.com'] };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('lowercase-normalizes and dedupes a valid allowedDomains list', async () => {
                mockState.pluginDoc = { config: { providers: [] } };
                const req = makeAuthedReq();
                req.body = { id: 'my-provider', preset: 'google', allowedDomains: ['Corp.Example.com', 'corp.example.com', ' partner.example.org '] };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersCreate(req, res);

                expect(global.CommonUtils.sendError).not.toHaveBeenCalled();
                expect(mockState.upsertedConfig.providers[0].allowedDomains).toEqual(['corp.example.com', 'partner.example.org']);
            });
        });

        describe('apiAdminProvidersUpdate', () => {
            test('updates a provider, keeping its clientSecretRef unchanged when no new secret is submitted', async () => {
                mockState.providerById = { id: 'google-corp', preset: 'google', label: 'Old Label', clientSecretRef: 'ref:authOauth_providers/google-corp/clientSecret' };
                mockState.pluginDoc = { config: { providers: [mockState.providerById] } };
                const req = makeAuthedReq({ params: { id: 'google-corp' } });
                req.body = { label: 'New Label', enabled: true };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersUpdate(req, res);

                expect(OauthProviderModel.setClientSecret).not.toHaveBeenCalled();
                expect(res.json).toHaveBeenCalledWith({
                    success: true,
                    data: expect.objectContaining({ id: 'google-corp', label: 'New Label', clientSecretRef: 'ref:authOauth_providers/google-corp/clientSecret' })
                });
            });

            test('re-encrypts and replaces the clientSecretRef when a new secret is submitted', async () => {
                mockState.providerById = { id: 'google-corp', preset: 'google', clientSecretRef: 'ref:old' };
                mockState.pluginDoc = { config: { providers: [mockState.providerById] } };
                const req = makeAuthedReq({ params: { id: 'google-corp' } });
                req.body = { clientSecret: 'new-secret' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersUpdate(req, res);

                expect(OauthProviderModel.setClientSecret).toHaveBeenCalledWith('google-corp', 'new-secret');
                expect(res.json).toHaveBeenCalledWith({
                    success: true,
                    data: expect.objectContaining({ clientSecretRef: 'ref:authOauth_providers/google-corp/clientSecret' })
                });
            });

            test('sends a 404 for an unknown provider id', async () => {
                mockState.providerById = null;
                const req = makeAuthedReq({ params: { id: 'does-not-exist' } });
                req.body = { label: 'X' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersUpdate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 404, expect.any(String), 'NOT_FOUND');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('rejects a non-hex buttonColor', async () => {
                mockState.providerById = { id: 'google-corp', preset: 'google' };
                mockState.pluginDoc = { config: { providers: [mockState.providerById] } };
                const req = makeAuthedReq({ params: { id: 'google-corp' } });
                req.body = { buttonColor: 'not-a-color' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersUpdate(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'VALIDATION_ERROR');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('sanitizes an icon containing markup on update', async () => {
                mockState.providerById = { id: 'google-corp', preset: 'oidc', icon: '🔐' };
                mockState.pluginDoc = { config: { providers: [mockState.providerById] } };
                const req = makeAuthedReq({ params: { id: 'google-corp' } });
                req.body = { icon: '<svg onload="alert(1)"><path d="M1 1"></path></svg>' };
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersUpdate(req, res);

                const saved = mockState.upsertedConfig.providers.find(p => p.id === 'google-corp');
                expect(saved.icon).not.toContain('onload');
                expect(saved.icon).not.toContain('alert');
                expect(saved.icon).toContain('<path');
            });
        });

        describe('apiAdminProvidersDelete', () => {
            test('removes the provider from config and deletes its stored secret', async () => {
                mockState.providerById = { id: 'google-corp', preset: 'google' };
                mockState.pluginDoc = { config: { providers: [mockState.providerById, { id: 'other', preset: 'oidc' }] } };
                const req = makeAuthedReq({ params: { id: 'google-corp' } });
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersDelete(req, res);

                expect(mockState.upsertedConfig.providers).toEqual([{ id: 'other', preset: 'oidc' }]);
                expect(OauthProviderModel.deleteClientSecret).toHaveBeenCalledWith('google-corp');
                expect(OauthProviderModel.invalidateCachedProviders).toHaveBeenCalled();
                expect(res.json).toHaveBeenCalledWith({ success: true });
            });

            test('sends a 404 for an unknown provider id', async () => {
                mockState.providerById = null;
                const req = makeAuthedReq({ params: { id: 'does-not-exist' } });
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersDelete(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 404, expect.any(String), 'NOT_FOUND');
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });
        });

        describe('apiAdminProvidersTest', () => {
            test('forces a fresh discovery and returns the resolved endpoints', async () => {
                mockState.providerWithSecret = { id: 'google-corp', type: 'oidc', preset: 'google', enabled: true };
                const req = makeAuthedReq({ params: { id: 'google-corp' } });
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersTest(req, res);

                expect(oauthClient.invalidateConfiguration).toHaveBeenCalledWith(mockState.providerWithSecret);
                expect(res.json).toHaveBeenCalledWith({
                    success: true,
                    data: {
                        issuer: 'https://idp.example.com',
                        authorizationEndpoint: 'https://idp.example.com/authorize',
                        tokenEndpoint: 'https://idp.example.com/token',
                        userinfoEndpoint: 'https://idp.example.com/userinfo',
                        jwksUri: 'https://idp.example.com/jwks'
                    }
                });
            });

            test('sends a 404 for an unknown provider id', async () => {
                mockState.providerWithSecret = null;
                const req = makeAuthedReq({ params: { id: 'does-not-exist' } });
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersTest(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 404, expect.any(String), 'NOT_FOUND');
            });

            test('sends PROVIDER_TEST_FAILED when discovery fails', async () => {
                mockState.providerWithSecret = { id: 'google-corp', type: 'oidc', preset: 'google', enabled: true };
                oauthClient.getConfiguration.mockRejectedValueOnce(new Error('discovery unreachable'));
                const req = makeAuthedReq({ params: { id: 'google-corp' } });
                const res = makeRes();

                await OauthAuthController.apiAdminProvidersTest(req, res);

                expect(global.CommonUtils.sendError).toHaveBeenCalledWith(req, res, 400, expect.any(String), 'PROVIDER_TEST_FAILED');
            });
        });

        describe('onPluginConfigBeforeSave hook (W-200: single Save button for the provider table)', () => {
            test('is a no-op when configData has no providers array (General/Security-only save)', async () => {
                const configData = { defaultLinkingStrategy: 'link-by-email' };
                await OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig: null });

                expect(configData).toEqual({ defaultLinkingStrategy: 'link-by-email' });
                expect(OauthProviderModel.setClientSecret).not.toHaveBeenCalled();
            });

            test('encrypts a submitted plaintext clientSecret and strips it from the persisted entry', async () => {
                const configData = { providers: [{ id: 'google-corp', preset: 'google', clientSecret: 'shh' }] };
                const oldConfig = { config: { providers: [] } };

                await OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig });

                expect(OauthProviderModel.setClientSecret).toHaveBeenCalledWith('google-corp', 'shh');
                expect(configData.providers[0].clientSecretRef).toBe('ref:authOauth_providers/google-corp/clientSecret');
                expect(configData.providers[0].clientSecret).toBeUndefined();
                expect(OauthProviderModel.invalidateCachedProviders).toHaveBeenCalled();
            });

            test('carries forward the existing clientSecretRef when clientSecret is left blank', async () => {
                const configData = { providers: [{ id: 'google-corp', preset: 'google', label: 'Updated Label' }] };
                const oldConfig = { config: { providers: [{ id: 'google-corp', preset: 'google', clientSecretRef: 'ref:authOauth_providers/google-corp/clientSecret' }] } };

                await OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig });

                expect(OauthProviderModel.setClientSecret).not.toHaveBeenCalled();
                expect(configData.providers[0].clientSecretRef).toBe('ref:authOauth_providers/google-corp/clientSecret');
                expect(configData.providers[0].label).toBe('Updated Label');
            });

            test('never trusts a client-submitted clientSecretRef - re-derives from the stored entry instead', async () => {
                const configData = { providers: [{ id: 'google-corp', preset: 'google', clientSecretRef: 'ref:attacker-supplied' }] };
                const oldConfig = { config: { providers: [{ id: 'google-corp', preset: 'google', clientSecretRef: 'ref:authOauth_providers/google-corp/clientSecret' }] } };

                await OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig });

                expect(configData.providers[0].clientSecretRef).toBe('ref:authOauth_providers/google-corp/clientSecret');
            });

            test('deletes the encrypted secret for a provider removed from the list', async () => {
                const configData = { providers: [] };
                const oldConfig = { config: { providers: [{ id: 'google-corp', preset: 'google', clientSecretRef: 'ref:authOauth_providers/google-corp/clientSecret' }] } };

                await OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig });

                expect(OauthProviderModel.deleteClientSecret).toHaveBeenCalledWith('google-corp');
            });

            test('sanitizes icon and allowedDomains for every provider in the list', async () => {
                const configData = {
                    providers: [{
                        id: 'google-corp', preset: 'oidc',
                        icon: '<svg onload="alert(1)"><path d="M1 1"></path></svg>',
                        allowedDomains: ['  Example.COM  ', 'example.com']
                    }]
                };
                const oldConfig = { config: { providers: [] } };

                await OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig });

                expect(configData.providers[0].icon).not.toContain('onload');
                expect(configData.providers[0].icon).toContain('<path');
                expect(configData.providers[0].allowedDomains).toEqual(['example.com']);
            });

            test('throws (aborting the save) on an invalid provider id', async () => {
                const configData = { providers: [{ id: 'bad id!', preset: 'google' }] };
                const oldConfig = { config: { providers: [] } };

                await expect(OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig }))
                    .rejects.toThrow(/Provider id is required/);
                expect(PluginModel.upsert).not.toHaveBeenCalled();
            });

            test('names a row without an id by position, so a leftover draft is findable', async () => {
                const configData = {
                    providers: [
                        { id: 'google-corp', preset: 'google' },
                        { id: '', preset: 'google' }
                    ]
                };

                await expect(OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig: { config: { providers: [] } } }))
                    .rejects.toThrow(/Provider in row 2: Provider id is required/);
            });

            test('throws on an unknown preset', async () => {
                const configData = { providers: [{ id: 'my-provider', preset: 'not-a-real-preset' }] };
                await expect(OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig: { config: { providers: [] } } }))
                    .rejects.toThrow(/Unknown preset/);
            });

            test('throws on a duplicate provider id within the submitted list', async () => {
                const configData = {
                    providers: [
                        { id: 'google-corp', preset: 'google' },
                        { id: 'google-corp', preset: 'oidc' }
                    ]
                };
                await expect(OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig: { config: { providers: [] } } }))
                    .rejects.toThrow(/Duplicate provider id/);
            });

            test('leaves an unmodified provider list untouched (no accidental clientSecret round-trip)', async () => {
                const stored = { id: 'google-corp', preset: 'google', clientSecretRef: 'ref:authOauth_providers/google-corp/clientSecret' };
                const configData = { providers: [{ ...stored }] };
                const oldConfig = { config: { providers: [stored] } };

                await OauthAuthController.onPluginConfigBeforeSave({ configData, oldConfig });

                expect(OauthProviderModel.setClientSecret).not.toHaveBeenCalled();
                expect(OauthProviderModel.deleteClientSecret).not.toHaveBeenCalled();
                expect(configData.providers[0]).toEqual(stored);
            });
        });
    });
});

// EOF plugins/auth-oauth/webapp/tests/unit/controller/oauth-auth.test.js
