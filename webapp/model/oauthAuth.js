/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Model / OAuth Auth
 * @tagline         user.oauth schema extension (W-107 cards) + link/unlink helpers
 * @description     Registers the `user.oauth` schema extension block with W-107 admin/user card
 *                   metadata, and provides read/link/unlink helpers over it. `user.oauth` is keyed
 *                   by provider id (a dynamic map, not a fixed field set), so unlike auth-mfa's
 *                   flat `mfa.*` fields, the card metadata here is a teaser only (a "Manage" action
 *                   that navigates to the dedicated linked-accounts page, see W-197 design doc §"UI
 *                   Components") rather than trying to model each provider as a W-107 field.
 * @file            plugins/auth-oauth/webapp/model/oauthAuth.js
 * @version         1.0.0
 * @release         2026-07-29
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import { ObjectId } from 'mongodb';

class OauthAuthModel {

    /** Called by the plugin loader (see OauthAuthController.initialize()) after bootstrap. */
    static initialize() {
        OauthAuthModel.registerSchemaExtension();
    }

    /** W-107: register the `user.oauth` extension block with admin/user card metadata. */
    static registerSchemaExtension() {
        if (!global.UserModel) {
            global.LogController?.logError(null, 'oauthAuth.registerSchemaExtension',
                'error: global.UserModel not available for schema extension');
            return;
        }

        global.UserModel.extendSchema({
            oauth: {
                _meta: {
                    plugin: 'auth-oauth',
                    adminCard: {
                        visible: true,
                        label: 'SSO Providers',
                        icon: '🔗',
                        description: 'Linked single sign-on identity providers for this user',
                        order: 90,
                        actions: [
                            {
                                id: 'manage',
                                label: 'Manage Providers',
                                style: 'secondary',
                                navigate: '/jpulse-plugins/auth-oauth.shtml'
                            }
                        ]
                    },
                    userCard: {
                        visible: true,
                        label: 'Connected Accounts',
                        icon: '🔗',
                        description: 'Sign in with Google, Okta, or other identity providers',
                        order: 20,
                        actions: [
                            {
                                id: 'manage',
                                label: 'Manage Connected Accounts',
                                style: 'primary',
                                navigate: '/jpulse-plugins/auth-oauth.shtml'
                            }
                        ]
                    }
                }
            }
        });
    }

    /**
     * List a user's linked providers as a plain array (for the linked-accounts page / cards).
     * @param {object} user - User document (with `oauth` block)
     * @returns {Array<object>} [{ providerId, sub, email, emailVerified, name, picture, linkedAt, lastLoginAt }]
     */
    static listLinkedProviders(user) {
        const oauth = user?.oauth || {};
        return Object.keys(oauth)
            .filter(providerId => providerId !== '_jit') // reserved sentinel (design doc §10), not a provider link
            .map(providerId => ({ providerId, ...oauth[providerId] }));
    }

    /**
     * Guard against removing a user's only sign-in method (design doc §11): if the user has no
     * usable local password (W-195 `hasLocalPassword`) and this is their last linked provider,
     * unlinking would permanently lock them out - point them at "Set Password" instead.
     * @param {object} user - User document
     * @param {string} providerId
     * @returns {{ allowed: boolean, reason?: string }}
     */
    static canUnlinkProvider(user, providerId) {
        if (!user?.oauth?.[providerId]) {
            return { allowed: false, reason: 'NOT_LINKED' };
        }
        const linkedCount = OauthAuthModel.listLinkedProviders(user).length;
        const hasLocalPassword = user.hasLocalPassword !== false;
        if (linkedCount <= 1 && !hasLocalPassword) {
            return { allowed: false, reason: 'LAST_SIGNIN_METHOD' };
        }
        return { allowed: true };
    }

    /**
     * Find the user (if any) a given provider `sub` is currently linked to - used to detect
     * sub-collisions when linking an additional provider to an already-logged-in user.
     * @param {string} providerId
     * @param {string} sub
     * @returns {Promise<object|null>}
     */
    static async findUserByProviderSub(providerId, sub) {
        const matches = await global.UserModel.find({ [`oauth.${providerId}.sub`]: sub }, { limit: 1 });
        return matches[0] || null;
    }

    /**
     * Remove a provider's oauth block from a user document. Uses a raw `$unset` on the collection
     * rather than `UserModel.updateById()`, which only ever issues `$set` (setting a key to
     * `undefined`/`null` would leave a stale value instead of removing the key).
     * @param {string} userId
     * @param {string} providerId
     * @returns {Promise<boolean>} True if a document was modified
     */
    static async unlinkProvider(userId, providerId) {
        const collection = global.UserModel.getCollection();
        const result = await collection.updateOne(
            { _id: new ObjectId(userId) },
            { $unset: { [`oauth.${providerId}`]: '' } }
        );
        return result.modifiedCount > 0;
    }
}

export default OauthAuthModel;

// EOF plugins/auth-oauth/webapp/model/oauthAuth.js
