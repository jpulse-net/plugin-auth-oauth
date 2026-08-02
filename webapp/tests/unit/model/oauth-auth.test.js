/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Tests / Unit / Model / OAuth Auth
 * @tagline         Unit tests for OauthAuthModel
 * @description     Tests the W-107 schema extension registration (against a mocked global.UserModel),
 *                   listLinkedProviders(), the unlink-last-method guard (canUnlinkProvider), and
 *                   unlinkProvider()'s raw $unset against a fake collection.
 * @file            plugins/auth-oauth/webapp/tests/unit/model/oauth-auth.test.js
 * @version         1.0.3
 * @release         2026-08-02
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import { describe, test, expect, jest, beforeAll, beforeEach } from '@jest/globals';
import { ObjectId } from 'mongodb';

describe('OauthAuthModel', () => {
    let OauthAuthModel;

    beforeAll(async () => {
        const mod = await import('../../../../webapp/model/oauthAuth.js');
        OauthAuthModel = mod.default;
    });

    describe('registerSchemaExtension / initialize', () => {
        test('registers the user.oauth block with adminCard/userCard metadata on global.UserModel', () => {
            global.UserModel = { extendSchema: jest.fn() };

            OauthAuthModel.initialize();

            expect(global.UserModel.extendSchema).toHaveBeenCalledTimes(1);
            const [schema] = global.UserModel.extendSchema.mock.calls[0];
            expect(schema.oauth._meta.plugin).toBe('auth-oauth');
            expect(schema.oauth._meta.adminCard.visible).toBe(true);
            expect(schema.oauth._meta.userCard.visible).toBe(true);
            expect(schema.oauth._meta.adminCard.actions[0].navigate).toBe('/jpulse-plugins/auth-oauth.shtml');
        });

        test('logs an error (does not throw) when global.UserModel is unavailable', () => {
            global.UserModel = undefined;
            global.LogController = { logError: jest.fn() };

            expect(() => OauthAuthModel.registerSchemaExtension()).not.toThrow();
            expect(global.LogController.logError).toHaveBeenCalled();
        });
    });

    describe('listLinkedProviders', () => {
        test('maps the oauth block into an array, excluding the reserved _jit sentinel', () => {
            const user = {
                oauth: {
                    'google-corp': { sub: 'sub-1', email: 'a@example.com' },
                    'okta-prod': { sub: 'sub-2', email: 'b@example.com' },
                    _jit: { pendingProfile: true }
                }
            };

            const linked = OauthAuthModel.listLinkedProviders(user);

            expect(linked).toHaveLength(2);
            expect(linked).toEqual(expect.arrayContaining([
                { providerId: 'google-corp', sub: 'sub-1', email: 'a@example.com' },
                { providerId: 'okta-prod', sub: 'sub-2', email: 'b@example.com' }
            ]));
        });

        test('returns an empty array when the user has no oauth block', () => {
            expect(OauthAuthModel.listLinkedProviders({})).toEqual([]);
            expect(OauthAuthModel.listLinkedProviders(null)).toEqual([]);
        });
    });

    describe('canUnlinkProvider', () => {
        test('refuses when the provider is not actually linked', () => {
            const result = OauthAuthModel.canUnlinkProvider({ oauth: {} }, 'google-corp');
            expect(result).toEqual({ allowed: false, reason: 'NOT_LINKED' });
        });

        test('allows unlinking when the user has a usable local password', () => {
            const user = { oauth: { 'google-corp': { sub: 's1' } }, hasLocalPassword: true };
            expect(OauthAuthModel.canUnlinkProvider(user, 'google-corp')).toEqual({ allowed: true });
        });

        test('allows unlinking when other providers remain linked, even without a local password', () => {
            const user = {
                oauth: { 'google-corp': { sub: 's1' }, 'okta-prod': { sub: 's2' } },
                hasLocalPassword: false
            };
            expect(OauthAuthModel.canUnlinkProvider(user, 'google-corp')).toEqual({ allowed: true });
        });

        test('blocks unlinking the only sign-in method when there is no usable local password', () => {
            const user = { oauth: { 'google-corp': { sub: 's1' } }, hasLocalPassword: false };
            expect(OauthAuthModel.canUnlinkProvider(user, 'google-corp')).toEqual({ allowed: false, reason: 'LAST_SIGNIN_METHOD' });
        });
    });

    describe('findUserByProviderSub', () => {
        test('delegates to global.UserModel.find() with a limit of 1 and returns the first match', async () => {
            const match = { _id: 'user-1' };
            global.UserModel = { find: jest.fn(async () => [match]) };

            const result = await OauthAuthModel.findUserByProviderSub('google-corp', 'sub-123');

            expect(global.UserModel.find).toHaveBeenCalledWith({ 'oauth.google-corp.sub': 'sub-123' }, { limit: 1 });
            expect(result).toBe(match);
        });

        test('returns null when there is no match', async () => {
            global.UserModel = { find: jest.fn(async () => []) };
            expect(await OauthAuthModel.findUserByProviderSub('google-corp', 'sub-404')).toBeNull();
        });
    });

    describe('unlinkProvider', () => {
        test('issues a raw $unset on the users collection and reports modifiedCount > 0 as success', async () => {
            const updateOne = jest.fn(async () => ({ modifiedCount: 1 }));
            global.UserModel = { getCollection: jest.fn(() => ({ updateOne })) };
            const userId = new ObjectId().toString();

            const result = await OauthAuthModel.unlinkProvider(userId, 'google-corp');

            expect(result).toBe(true);
            expect(updateOne).toHaveBeenCalledWith(
                { _id: expect.any(ObjectId) },
                { $unset: { 'oauth.google-corp': '' } }
            );
        });

        test('returns false when nothing was modified', async () => {
            const updateOne = jest.fn(async () => ({ modifiedCount: 0 }));
            global.UserModel = { getCollection: jest.fn(() => ({ updateOne })) };

            const result = await OauthAuthModel.unlinkProvider(new ObjectId().toString(), 'google-corp');

            expect(result).toBe(false);
        });
    });
});

// EOF plugins/auth-oauth/webapp/tests/unit/model/oauth-auth.test.js
