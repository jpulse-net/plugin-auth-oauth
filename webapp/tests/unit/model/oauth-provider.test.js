/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Tests / Unit / Model / OAuth Provider
 * @tagline         Unit tests for OauthProviderModel
 * @description     Tests provider list reads (via mocked PluginModel), client secret
 *                   encryption round-trip through a mocked authOauth_providers collection, and
 *                   getProviderWithSecret() merging preset defaults + decrypted secret
 * @file            plugins/auth-oauth/webapp/tests/unit/model/oauth-provider.test.js
 * @version         1.0.3
 * @release         2026-08-02
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import { describe, test, expect, jest, beforeEach } from '@jest/globals';

// In-memory fake collection standing in for `authOauth_providers`
function makeFakeCollection() {
    const docs = new Map();
    return {
        _docs: docs,
        findOne: jest.fn(async (query) => docs.get(query.providerId) || null),
        updateOne: jest.fn(async (query, update, options) => {
            const existing = docs.get(query.providerId);
            if (!existing && !options?.upsert) {
                return { matchedCount: 0, upsertedCount: 0 };
            }
            const merged = { ...(existing || update.$setOnInsert), ...update.$set };
            docs.set(query.providerId, merged);
            return { matchedCount: existing ? 1 : 0, upsertedCount: existing ? 0 : 1 };
        }),
        deleteOne: jest.fn(async (query) => {
            const had = docs.has(query.providerId);
            docs.delete(query.providerId);
            return { deletedCount: had ? 1 : 0 };
        })
    };
}

// Jest hoists jest.mock() factories above imports and forbids them from closing over
// out-of-scope variables unless the variable name starts with "mock" (case-insensitive) -
// hence mockState instead of the more natural fakeCollection/fakePluginDoc names below.
const mockState = { collection: null, pluginDoc: null };

jest.mock('../../../../../../webapp/database.js', () => ({
    __esModule: true,
    default: { getDb: jest.fn(() => ({ collection: jest.fn(() => mockState.collection) })) }
}));

jest.mock('../../../../../../webapp/model/plugin.js', () => ({
    __esModule: true,
    default: { getByName: jest.fn(async () => mockState.pluginDoc) }
}));

describe('OauthProviderModel', () => {
    let OauthProviderModel;

    beforeAll(async () => {
        global.appConfig = { security: { sessionSecret: 'test-session-secret-for-unit-tests' } };
        const mod = await import('../../../../webapp/model/oauthProvider.js');
        OauthProviderModel = mod.default;
    });

    beforeEach(() => {
        mockState.collection = makeFakeCollection();
        mockState.pluginDoc = {
            config: {
                providers: [
                    { id: 'google-corp', preset: 'google', label: 'Sign in with Google', enabled: true, order: 10 },
                    { id: 'okta-prod', preset: 'oidc', label: 'Sign in with Okta', enabled: false, order: 20,
                        discoveryUrl: 'https://myorg.okta.com/.well-known/openid-configuration' }
                ]
            }
        };
    });

    describe('getProviders / getProviderById', () => {
        test('returns the stored provider list as-is (no secrets)', async () => {
            const providers = await OauthProviderModel.getProviders();
            expect(providers).toHaveLength(2);
            expect(providers[0]).not.toHaveProperty('clientSecret');
        });

        test('returns an empty array when no config exists yet', async () => {
            mockState.pluginDoc = null;
            const providers = await OauthProviderModel.getProviders();
            expect(providers).toEqual([]);
        });

        test('finds a provider entry by id', async () => {
            const provider = await OauthProviderModel.getProviderById('okta-prod');
            expect(provider.label).toBe('Sign in with Okta');
        });

        test('returns null for an unknown provider id', async () => {
            expect(await OauthProviderModel.getProviderById('does-not-exist')).toBeNull();
        });
    });

    describe('client secret storage', () => {
        test('setClientSecret returns a ref string and does not store the plaintext', async () => {
            const ref = await OauthProviderModel.setClientSecret('google-corp', 'super-secret-value');

            expect(ref).toBe('ref:authOauth_providers/google-corp/clientSecret');
            const stored = mockState.collection._docs.get('google-corp');
            expect(stored.clientSecretEncrypted).toBeDefined();
            expect(stored.clientSecretEncrypted).not.toContain('super-secret-value');
        });

        test('getClientSecret decrypts back to the original plaintext', async () => {
            await OauthProviderModel.setClientSecret('google-corp', 'super-secret-value');
            const decrypted = await OauthProviderModel.getClientSecret('google-corp');
            expect(decrypted).toBe('super-secret-value');
        });

        test('getClientSecret returns null when nothing is stored for that provider', async () => {
            expect(await OauthProviderModel.getClientSecret('never-set')).toBeNull();
        });

        test('setClientSecret upserts on repeated calls (updates, does not duplicate)', async () => {
            await OauthProviderModel.setClientSecret('google-corp', 'first-value');
            await OauthProviderModel.setClientSecret('google-corp', 'second-value');

            expect(await OauthProviderModel.getClientSecret('google-corp')).toBe('second-value');
            expect(mockState.collection._docs.size).toBe(1);
        });

        test('deleteClientSecret removes the stored secret', async () => {
            await OauthProviderModel.setClientSecret('google-corp', 'super-secret-value');
            const deleted = await OauthProviderModel.deleteClientSecret('google-corp');

            expect(deleted).toBe(true);
            expect(await OauthProviderModel.getClientSecret('google-corp')).toBeNull();
        });

        test('rejects setting an empty secret', async () => {
            await expect(OauthProviderModel.setClientSecret('google-corp', '')).rejects.toThrow();
        });

        test('rejects setting a secret without a providerId', async () => {
            await expect(OauthProviderModel.setClientSecret('', 'some-secret')).rejects.toThrow();
        });
    });

    describe('getProviderWithSecret', () => {
        test('merges preset defaults, stored overrides, and the decrypted secret', async () => {
            await OauthProviderModel.setClientSecret('google-corp', 'super-secret-value');

            const merged = await OauthProviderModel.getProviderWithSecret('google-corp');

            expect(merged.clientSecret).toBe('super-secret-value');
            expect(merged.discoveryUrl).toBe('https://accounts.google.com/.well-known/openid-configuration');
            expect(merged.label).toBe('Sign in with Google');
            expect(merged.scopes).toEqual(['openid', 'email', 'profile']);
        });

        test('returns null when the provider is not configured', async () => {
            expect(await OauthProviderModel.getProviderWithSecret('does-not-exist')).toBeNull();
        });

        test('returns clientSecret: null when no secret has been set yet', async () => {
            const merged = await OauthProviderModel.getProviderWithSecret('okta-prod');
            expect(merged.clientSecret).toBeNull();
        });
    });

    describe('getCachedProviders / invalidateCachedProviders (§13)', () => {
        let redisStore;

        beforeEach(() => {
            redisStore = new Map();
            global.RedisManager = {
                cacheGetObject: jest.fn(async (path, key) => redisStore.get(`${path}:${key}`) || null),
                cacheSetObject: jest.fn(async (path, key, obj) => { redisStore.set(`${path}:${key}`, obj); return true; }),
                cacheDel: jest.fn(async (path, key) => redisStore.delete(`${path}:${key}`))
            };
        });

        test('reads through PluginModel on a cache miss, then serves the cache on the next call', async () => {
            const first = await OauthProviderModel.getCachedProviders();
            expect(first).toHaveLength(2);
            expect(global.RedisManager.cacheSetObject).toHaveBeenCalledWith(
                'plugin:auth-oauth:config', 'providers', first, expect.objectContaining({ ttl: expect.any(Number) }));

            mockState.pluginDoc = { config: { providers: [] } }; // change underlying data
            const second = await OauthProviderModel.getCachedProviders();
            expect(second).toHaveLength(2); // still served from cache, not the (now-empty) underlying config
        });

        test('falls back to the uncached read when Redis is unavailable (fail-open)', async () => {
            global.RedisManager = undefined;
            const providers = await OauthProviderModel.getCachedProviders();
            expect(providers).toHaveLength(2);
        });

        test('invalidateCachedProviders clears the cache so the next read is fresh', async () => {
            await OauthProviderModel.getCachedProviders();
            mockState.pluginDoc = { config: { providers: [] } };

            await OauthProviderModel.invalidateCachedProviders();
            const afterInvalidate = await OauthProviderModel.getCachedProviders();

            expect(afterInvalidate).toEqual([]);
        });
    });
});

// EOF plugins/auth-oauth/webapp/tests/unit/model/oauth-provider.test.js
