/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Model / OAuth Provider
 * @tagline         Provider config reads + client secret storage
 * @description     Reads the admin-configured provider list from plugin config (pluginConfigs
 *                   collection, via PluginModel), and manages client secrets at rest in a
 *                   dedicated `authOauth_providers` collection - kept separate from
 *                   `pluginConfigs` (a heavily-read collection on every request) so secrets get
 *                   their own access boundary. See W-197 design doc §8.
 * @file            plugins/auth-oauth/webapp/model/oauthProvider.js
 * @version         1.0.1
 * @release         2026-07-31
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import database from '../../../../webapp/database.js';
import PluginModel from '../../../../webapp/model/plugin.js';
import { encryptSecret, decryptSecret } from '../../../../webapp/utils/crypto-secrets.js';
import { resolveProviderConfig } from '../utils/providerRegistry.js';

const COLLECTION_NAME = 'authOauth_providers';
const SECRET_SALT = 'oauth-provider-salt';
const CONFIG_CACHE_PATH = 'plugin:auth-oauth:config';
const CONFIG_CACHE_KEY = 'providers';
const CONFIG_CACHE_TTL_SECONDS = 20;

class OauthProviderModel {

    /**
     * @returns {import('mongodb').Collection} The authOauth_providers collection
     */
    static getCollection() {
        const db = database.getDb();
        if (!db) {
            throw new Error('OauthProviderModel: database connection not available');
        }
        return db.collection(COLLECTION_NAME);
    }

    /**
     * Read the raw provider list from plugin config (pluginConfigs.config.providers).
     * Callers on a hot path (e.g. the login-page hook, see §13) should use getCachedProviders()
     * instead - this is an uncached MongoDB read via PluginModel every time.
     * @returns {Promise<object[]>} Provider entries as stored (no secrets - see getProviderWithSecret)
     */
    static async getProviders() {
        const pluginDoc = await PluginModel.getByName('auth-oauth');
        return pluginDoc?.config?.providers || [];
    }

    /**
     * §13 (found during spec review): short-TTL Redis cache in front of getProviders(), for
     * `onAuthGetLoginProviders` / `apiProviders` - both run on every unauthenticated render of
     * `/auth/login.shtml`, the highest-traffic unauthenticated route on the site. A ~20s staleness
     * window on provider *metadata* (label/icon/enabled/order - never secrets) is an acceptable
     * trade for admins toggling a provider; `RedisManager.cacheGetObject`/`cacheSetObject` already
     * fail open when Redis is unavailable, degrading automatically to the uncached read below - no
     * separate in-memory fallback needed. The actual token exchange (getProviderWithSecret(), used
     * by apiInit/apiCallback) always reads fresh/uncached - that path is far lower-traffic and
     * correctness there matters more than a few seconds of caching.
     * @returns {Promise<object[]>}
     */
    static async getCachedProviders() {
        const cached = await global.RedisManager?.cacheGetObject(CONFIG_CACHE_PATH, CONFIG_CACHE_KEY);
        if (cached) {
            return cached;
        }
        const providers = await OauthProviderModel.getProviders();
        await global.RedisManager?.cacheSetObject(CONFIG_CACHE_PATH, CONFIG_CACHE_KEY, providers,
            { ttl: CONFIG_CACHE_TTL_SECONDS });
        return providers;
    }

    /**
     * Invalidate the §13 provider cache - call after any admin write to the provider list so the
     * login page doesn't serve a stale button set for up to CONFIG_CACHE_TTL_SECONDS.
     * @returns {Promise<void>}
     */
    static async invalidateCachedProviders() {
        await global.RedisManager?.cacheDel(CONFIG_CACHE_PATH, CONFIG_CACHE_KEY);
    }

    /**
     * Find one provider entry (metadata only, no secret) by its admin-chosen id.
     * @param {string} providerId
     * @returns {Promise<object|null>}
     */
    static async getProviderById(providerId) {
        const providers = await OauthProviderModel.getProviders();
        return providers.find(p => p.id === providerId) || null;
    }

    /**
     * Resolve a provider's full effective config (preset defaults + stored overrides) plus its
     * decrypted client secret, ready to hand to the OIDC/OAuth2 client wrapper. Never expose the
     * return value of this function outside of server-side token-exchange code paths.
     * @param {string} providerId
     * @returns {Promise<object|null>} { ...resolvedConfig, clientSecret } or null if not found
     */
    static async getProviderWithSecret(providerId) {
        const providerConfig = await OauthProviderModel.getProviderById(providerId);
        if (!providerConfig) {
            return null;
        }
        const resolved = resolveProviderConfig(providerConfig);
        const clientSecret = await OauthProviderModel.getClientSecret(providerId);
        return { ...resolved, clientSecret };
    }

    /**
     * Encrypt and store (upsert) a provider's client secret. Returns a reference string that gets
     * saved in the provider's `clientSecretRef` field in the providers config array - never the
     * plaintext or ciphertext itself.
     * @param {string} providerId
     * @param {string} plaintextSecret
     * @returns {Promise<string>} e.g. 'ref:authOauth_providers/<providerId>/clientSecret'
     */
    static async setClientSecret(providerId, plaintextSecret) {
        if (!providerId) {
            throw new Error('OauthProviderModel.setClientSecret: providerId is required');
        }
        if (!plaintextSecret) {
            throw new Error('OauthProviderModel.setClientSecret: plaintextSecret is required');
        }
        const encrypted = encryptSecret(plaintextSecret, SECRET_SALT);
        const collection = OauthProviderModel.getCollection();
        const now = new Date();
        await collection.updateOne(
            { providerId },
            { $set: { providerId, clientSecretEncrypted: encrypted, updatedAt: now },
              $setOnInsert: { createdAt: now } },
            { upsert: true }
        );
        return `ref:${COLLECTION_NAME}/${providerId}/clientSecret`;
    }

    /**
     * Decrypt and return a provider's client secret. Only ever called from server-side
     * token-exchange code (init/callback/test-connection) - never returned in any API response.
     * @param {string} providerId
     * @returns {Promise<string|null>} Decrypted secret, or null if none stored
     */
    static async getClientSecret(providerId) {
        const collection = OauthProviderModel.getCollection();
        const doc = await collection.findOne({ providerId });
        if (!doc?.clientSecretEncrypted) {
            return null;
        }
        return decryptSecret(doc.clientSecretEncrypted, SECRET_SALT);
    }

    /**
     * Remove a provider's stored secret (e.g. when the provider is deleted from config).
     * @param {string} providerId
     * @returns {Promise<boolean>} True if a document was deleted
     */
    static async deleteClientSecret(providerId) {
        const collection = OauthProviderModel.getCollection();
        const result = await collection.deleteOne({ providerId });
        return result.deletedCount > 0;
    }
}

export default OauthProviderModel;

// EOF plugins/auth-oauth/webapp/model/oauthProvider.js
