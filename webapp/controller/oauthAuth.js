/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Controller / OAuth Auth
 * @tagline         OAuth 2.0 / OIDC login endpoints (init + callback) and hooks
 * @description     Handles the browser-redirect Authorization Code + PKCE flow: apiInit starts
 *                   it (state/nonce/PKCE generation, redirect to the provider), apiCallback
 *                   finishes it (token exchange, ID token verification, user resolution, and
 *                   handing off to AuthController.completeExternalAuth() from W-195).
 *                   Also provides the `onAuthGetLoginProviders` hook (login page buttons, §13
 *                   cached), the authenticated link/unlink endpoints for the linked-accounts page
 *                   (apiUserProviders/apiLink/apiUnlink), and the `jit-create` new-user
 *                   provisioning flow: _resolveUser() creates a schema-conformant user document
 *                   immediately (Stage A best-effort extraction via profileExtractor.js - see
 *                   _createJitUser()), then `onAuthGetSteps`/`onAuthValidateStep` inject/validate
 *                   an `oauth-profile-complete` step into the existing W-109 multi-step login
 *                   flow (Stage B) only if the IdP didn't provide all required profile fields -
 *                   apiProfileDraft is a read-only helper for that step's view, not a separate
 *                   submission path (submission goes through the shared POST /api/1/auth/login,
 *                   design doc §10).
 *                   apiCallback branches on `pending.mode` ('login' vs 'link') to serve both
 *                   apiInit and apiLink from the same callback route; within 'login' mode,
 *                   _resolveUser()'s three linking strategies (`sub-only`, `link-by-email`,
 *                   `jit-create`) are all implemented - see that method's doc comment.
 *                   apiAdminProviders* (list/create/update/delete/test) back the W-194 custom
 *                   renderer (webapp/view/jpulse-common.js authOauth.renderProviders) - each
 *                   write reads the plugin's full config via PluginModel, splices the `providers`
 *                   array, and writes it back via PluginModel.upsert() (design doc §8), encrypting
 *                   any submitted plaintext `clientSecret` via OauthProviderModel.setClientSecret()
 *                   before it ever reaches config storage, and invalidating the §13 login-page
 *                   cache on every write.
 * @file            plugins/auth-oauth/webapp/controller/oauthAuth.js
 * @version         1.0.0
 * @release         2026-07-29
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import crypto from 'crypto';
import UserModel from '../../../../webapp/model/user.js';
import PluginModel from '../../../../webapp/model/plugin.js';
import AuthController from '../../../../webapp/controller/auth.js';
import OauthProviderModel from '../model/oauthProvider.js';
import OauthAuthModel from '../model/oauthAuth.js';
import * as oauthClient from '../utils/oauthClient.js';
import { extractProfile } from '../utils/profileExtractor.js';
import { isValidPreset } from '../utils/providerRegistry.js';

const PROVIDER_ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;
const BUTTON_COLOR_PATTERN = /^#[0-9a-fA-F]{6}$/;

// Small, deliberately conservative SVG allow-list for the `icon` field (single-color line/shape
// icons only - see W-197 design doc "button color" discussion). Tag/attribute names must be
// lowercase: CommonUtils.sanitizeHtml() lowercases both before comparing against these lists, and
// the HTML parser's own "adjust SVG attribute names" step (e.g. viewbox -> viewBox) fixes casing
// back up when the browser renders the result, so lowercase-only here is not a functional loss.
const ICON_SVG_ALLOWED_TAGS = ['svg', 'path', 'g', 'circle', 'rect', 'line', 'polyline', 'polygon'];
const ICON_SVG_ALLOWED_ATTRIBUTES = {
    svg: ['viewbox', 'xmlns', 'width', 'height', 'fill'],
    path: ['d', 'fill', 'stroke', 'stroke-width', 'fill-rule'],
    g: ['fill', 'stroke'],
    circle: ['cx', 'cy', 'r', 'fill', 'stroke'],
    rect: ['x', 'y', 'width', 'height', 'rx', 'ry', 'fill', 'stroke'],
    line: ['x1', 'y1', 'x2', 'y2', 'stroke', 'stroke-width'],
    polyline: ['points', 'fill', 'stroke'],
    polygon: ['points', 'fill', 'stroke']
};

const PENDING_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes - matches W-195 pendingAuth convention
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX_REQUESTS = 60; // per IP per window, per design doc §"Security Requirements"

/**
 * Best-effort client IP extraction (X-Forwarded-For first hop, then req.ip) - mirrors the
 * priority order CommonUtils uses elsewhere in the framework for log context.
 */
function getClientIp(req) {
    if (req.headers?.['x-forwarded-for']) {
        return req.headers['x-forwarded-for'].split(',')[0].trim();
    }
    return req.headers?.['x-real-ip']?.trim() || req.ip || req.connection?.remoteAddress || 'unknown';
}

/** Compute this deployment's callback redirect_uri for a provider (design doc §8). */
function computeRedirectUri(req, providerId) {
    return `${req.protocol}://${req.get('host')}/api/1/auth-oauth/callback/${encodeURIComponent(providerId)}`;
}

/** Map a provider's raw userinfo response through its admin-configured field mapping (custom OAuth2 preset). */
function mapUserinfoToClaims(userinfo, mapping) {
    if (!mapping) {
        return userinfo || {};
    }
    const mapped = {};
    for (const [claimName, sourceField] of Object.entries(mapping)) {
        mapped[claimName] = userinfo?.[sourceField];
    }
    return mapped;
}

/**
 * Strip `admin`/`root` from JIT default roles (design doc §8 "Defense in depth" - the UI only
 * offering `user` in the dropdown is a UX nicety, not the actual security boundary; this is).
 */
function sanitizeJitRoles(roles) {
    const list = Array.isArray(roles) && roles.length > 0 ? roles : ['user'];
    const filtered = list.filter(r => r !== 'admin' && r !== 'root');
    return filtered.length > 0 ? filtered : ['user'];
}

/**
 * `icon` renders raw/unescaped on the login page (webapp/view/auth/login.shtml `{{this.icon}}`
 * - the framework template can't be changed to escape it, so this plugin must guarantee it's
 * safe before it's ever stored). Plain text/emoji (the common case, no "<") passes through
 * unchanged; anything that looks like markup is run through the framework's allow-list
 * sanitizer so only inert single-color SVG shapes can survive - see ICON_SVG_ALLOWED_TAGS.
 */
function sanitizeIcon(icon) {
    if (typeof icon !== 'string' || !icon.includes('<')) {
        return icon;
    }
    return global.CommonUtils.sanitizeHtml(icon, {
        allowedTags: ICON_SVG_ALLOWED_TAGS,
        allowedAttributes: ICON_SVG_ALLOWED_ATTRIBUTES
    });
}

class OauthAuthController {

    // Auto-registered by PluginManager during bootstrap (see auth-mfa for the same pattern).
    static hooks = {
        onAuthGetLoginProviders: { priority: 100 },
        // W-109: inject/validate the oauth-profile-complete step for jit-create users whose IdP
        // didn't provide all required profile fields (design doc §10 Stage B).
        onAuthGetSteps: { priority: 20 },
        onAuthValidateStep: { priority: 100 }
    };

    static routes = [
        { method: 'GET', path: '/api/1/auth-oauth/providers', handler: 'apiProviders', auth: 'none' },
        { method: 'GET', path: '/api/1/auth-oauth/init/:provider', handler: 'apiInit', auth: 'none' },
        { method: 'GET', path: '/api/1/auth-oauth/callback/:provider', handler: 'apiCallback', auth: 'none' },
        { method: 'GET', path: '/api/1/auth-oauth/user/providers', handler: 'apiUserProviders', auth: 'user' },
        { method: 'POST', path: '/api/1/auth-oauth/link/:provider', handler: 'apiLink', auth: 'user' },
        { method: 'DELETE', path: '/api/1/auth-oauth/link/:provider', handler: 'apiUnlink', auth: 'user' },
        // Unauthenticated (see file header) - gated by req.session.pendingAuth, not a user session;
        // this is a read-only helper for the oauth-profile-complete.shtml Stage B form, not itself
        // part of the multi-step contract (submission goes through the shared POST /api/1/auth/login).
        { method: 'GET', path: '/api/1/auth-oauth/profile-draft', handler: 'apiProfileDraft', auth: 'none' },
        // Back the W-194 custom renderer's provider table (§13's admin/plugin-config.shtml Save
        // button also persists `providers` as part of the whole-form save, but these dedicated
        // endpoints are what actually encrypt a submitted clientSecret and run "Test Connection").
        { method: 'GET', path: '/api/1/auth-oauth/admin/providers', handler: 'apiAdminProviders', auth: 'admin' },
        { method: 'POST', path: '/api/1/auth-oauth/admin/providers', handler: 'apiAdminProvidersCreate', auth: 'admin' },
        { method: 'PUT', path: '/api/1/auth-oauth/admin/providers/:id', handler: 'apiAdminProvidersUpdate', auth: 'admin' },
        { method: 'DELETE', path: '/api/1/auth-oauth/admin/providers/:id', handler: 'apiAdminProvidersDelete', auth: 'admin' },
        { method: 'POST', path: '/api/1/auth-oauth/admin/providers/:id/test', handler: 'apiAdminProvidersTest', auth: 'admin' }
    ];

    /** Called by the plugin loader after bootstrap - registers the user.oauth schema extension. */
    static async initialize() {
        OauthAuthModel.initialize();
    }

    /**
     * Redirect to the plugin's error landing page instead of exposing raw provider/library errors.
     * See W-197 design doc "Security Requirements" and "UI Components" §5.
     */
    static redirectToError(req, res, reason) {
        return res.redirect(`/auth/oauth-error.shtml?reason=${encodeURIComponent(reason)}`);
    }

    /** Map raw provider config entries to the small public shape used for login page buttons. */
    static _buildProviderButtons(providers) {
        return providers
            .filter(p => p.enabled)
            .map(p => ({
                id: p.id,
                label: p.label,
                icon: p.icon,
                buttonColor: p.buttonColor,
                initUrl: `/api/1/auth-oauth/init/${encodeURIComponent(p.id)}`,
                order: p.order || 100
            }))
            .sort((a, b) => a.order - b.order);
    }

    /**
     * W-195 hook: inject this plugin's enabled provider buttons into the login page. Runs on
     * every unauthenticated render of /auth/login.shtml - reads through the §13 short-TTL cache.
     * @param {object} context - { req, providers } (canModify: true - push into `providers`)
     */
    static async onAuthGetLoginProviders(context) {
        try {
            const providers = await OauthProviderModel.getCachedProviders();
            context.providers.push(...OauthAuthController._buildProviderButtons(providers));
        } catch (error) {
            global.LogController.logWarning(context.req, 'oauthAuth.onAuthGetLoginProviders', `warning: ${error.message}`);
        }
        return context;
    }

    /**
     * GET /api/1/auth-oauth/providers
     * List enabled providers (metadata only, no secrets) - §13 cached read (see file header).
     */
    static async apiProviders(req, res) {
        global.LogController.logRequest(req, 'oauthAuth.apiProviders', '');
        try {
            const providers = await OauthProviderModel.getCachedProviders();
            const enabled = OauthAuthController._buildProviderButtons(providers);
            global.LogController.logInfo(req, 'oauthAuth.apiProviders', `success: ${enabled.length} enabled provider(s)`);
            return res.json({ success: true, data: enabled });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiProviders', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to list providers', 'INTERNAL_ERROR');
        }
    }

    /**
     * GET /api/1/auth-oauth/user/providers
     * List the authenticated user's linked providers (plus which unlinked-enabled providers are
     * still available to connect) for the linked-accounts page.
     */
    static async apiUserProviders(req, res) {
        global.LogController.logRequest(req, 'oauthAuth.apiUserProviders', req.session.user.username);
        try {
            const user = await UserModel.findById(req.session.user.id);
            if (!user) {
                return global.CommonUtils.sendError(req, res, 404, 'User not found', 'NOT_FOUND');
            }

            const allProviders = await OauthProviderModel.getProviders();
            const linked = OauthAuthModel.listLinkedProviders(user).map(link => {
                const meta = allProviders.find(p => p.id === link.providerId) || {};
                const unlinkCheck = OauthAuthModel.canUnlinkProvider(user, link.providerId);
                return {
                    providerId: link.providerId,
                    label: meta.label || link.providerId,
                    icon: meta.icon || '🔗',
                    email: link.email || null,
                    linkedAt: link.linkedAt || null,
                    lastLoginAt: link.lastLoginAt || null,
                    canUnlink: unlinkCheck.allowed,
                    unlinkBlockedReason: unlinkCheck.allowed ? null : unlinkCheck.reason
                };
            });
            const available = allProviders
                .filter(p => p.enabled && !user.oauth?.[p.id])
                .map(p => ({
                    providerId: p.id,
                    label: p.label,
                    icon: p.icon,
                    linkUrl: `/api/1/auth-oauth/link/${encodeURIComponent(p.id)}`
                }));

            global.LogController.logInfo(req, 'oauthAuth.apiUserProviders',
                `success: ${linked.length} linked, ${available.length} available for user ${user.username}`);
            return res.json({
                success: true,
                data: { linked, available, hasLocalPassword: user.hasLocalPassword !== false }
            });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiUserProviders', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to list linked providers', 'INTERNAL_ERROR');
        }
    }

    /**
     * POST /api/1/auth-oauth/link/:provider
     * Start a link flow for the already-authenticated user: same PKCE/state/nonce mechanics as
     * apiInit, but returns JSON (the caller's JS does the actual `window.location` navigation)
     * instead of a 302, and stamps `userId` into oauthPending so apiCallback can verify the same
     * session completes the flow.
     */
    static async apiLink(req, res) {
        const providerId = req.params.provider;
        global.LogController.logRequest(req, 'oauthAuth.apiLink', `${req.session.user.username} -> ${providerId}`);

        try {
            const result = await OauthAuthController._startAuthorizationFlow(req, providerId, 'link', {
                userId: req.session.user.id,
                redirectUrl: '/jpulse-plugins/auth-oauth.shtml'
            });
            if (result.error) {
                global.LogController.logError(req, 'oauthAuth.apiLink', `error: ${result.error} for provider ${providerId}`);
                return global.CommonUtils.sendError(req, res, 404, 'Provider not found or disabled', result.error);
            }

            global.LogController.logInfo(req, 'oauthAuth.apiLink', `success: starting link flow for provider ${providerId}`);
            return res.json({ success: true, data: { redirectUrl: result.authUrl.href } });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiLink', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to start link flow', 'INTERNAL_ERROR');
        }
    }

    /**
     * DELETE /api/1/auth-oauth/link/:provider
     * Unlink a provider from the authenticated user, unless it's their only sign-in method and
     * they have no usable local password (design doc §11 - see OauthAuthModel.canUnlinkProvider).
     */
    static async apiUnlink(req, res) {
        const providerId = req.params.provider;
        global.LogController.logRequest(req, 'oauthAuth.apiUnlink', `${req.session.user.username} -> ${providerId}`);

        try {
            const user = await UserModel.findById(req.session.user.id);
            if (!user) {
                return global.CommonUtils.sendError(req, res, 404, 'User not found', 'NOT_FOUND');
            }

            const check = OauthAuthModel.canUnlinkProvider(user, providerId);
            if (!check.allowed) {
                global.LogController.logError(req, 'oauthAuth.apiUnlink',
                    `error: ${check.reason} for user ${user.username}, provider ${providerId}`);
                const message = check.reason === 'LAST_SIGNIN_METHOD'
                    ? 'This is your only sign-in method. Set a local password before disconnecting it.'
                    : 'Provider is not linked to your account';
                return global.CommonUtils.sendError(req, res, 400, message, check.reason);
            }

            await OauthAuthModel.unlinkProvider(user._id, providerId);
            global.LogController.logInfo(req, 'oauthAuth.apiUnlink', `success: unlinked provider ${providerId} for user ${user.username}`);
            return res.json({ success: true });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiUnlink', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to unlink provider', 'INTERNAL_ERROR');
        }
    }

    /**
     * GET /api/1/auth-oauth/admin/providers
     * List all configured providers (raw config incl. `clientSecretRef`, never the secret itself
     * - see model/oauthProvider.js) for the W-194 custom renderer.
     */
    static async apiAdminProviders(req, res) {
        global.LogController.logRequest(req, 'oauthAuth.apiAdminProviders', '');
        try {
            const providers = await OauthProviderModel.getProviders();
            global.LogController.logInfo(req, 'oauthAuth.apiAdminProviders', `success: ${providers.length} provider(s)`);
            return res.json({ success: true, data: providers });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiAdminProviders', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to list providers', 'INTERNAL_ERROR');
        }
    }

    /**
     * Shared validation for apiAdminProvidersCreate/apiAdminProvidersUpdate: `id` format,
     * `preset` recognized, `buttonColor` format, `label` plain-text. Uniqueness (create) is
     * checked by the caller against the current list. `icon` is not validated here - it's
     * sanitized (not rejected) at the call site via sanitizeIcon(), since "is this valid SVG"
     * isn't a simple format check the way the other fields are.
     * @returns {string|null} Error message, or null if valid
     */
    static _validateProviderInput(body, { requireId }) {
        if (requireId && !PROVIDER_ID_PATTERN.test(body?.id || '')) {
            return 'Provider id is required and may only contain letters, digits, "-" and "_"';
        }
        if (body?.preset !== undefined && !isValidPreset(body.preset)) {
            return `Unknown preset '${body.preset}'`;
        }
        // buttonColor is interpolated directly into a `style="border-color: ...;"` attribute on
        // the login page (framework-owned template, raw/unescaped) - a strict hex format check
        // both keeps the field meaningful and incidentally rules out attribute-breakout payloads.
        if (body?.buttonColor !== undefined && body.buttonColor !== '' && !BUTTON_COLOR_PATTERN.test(body.buttonColor)) {
            return 'Button color must be a 6-digit hex color (e.g. #4285F4)';
        }
        // label also renders raw/unescaped (see sanitizeIcon() doc comment) - it's a short plain
        // text field, so simply rejecting "<"/">" is sufficient and clearer than sanitizing it.
        if (body?.label !== undefined && /[<>]/.test(body.label)) {
            return 'Label may not contain "<" or ">"';
        }
        return null;
    }

    /**
     * Read the full plugin config, splice a new/updated/removed entry into `config.providers`,
     * write it back via PluginModel.upsert(), and invalidate the §13 login-page cache. Centralizes
     * the read-modify-write so create/update/delete can't race each other into clobbering an
     * unrelated field on the plugin's config object.
     * @param {(providers: object[]) => object[]} mutate - Returns the new providers array
     * @returns {Promise<object>} The full config object that was saved
     */
    static async _saveProviders(req, mutate) {
        const pluginDoc = await PluginModel.getByName('auth-oauth');
        const config = { ...(pluginDoc?.config || {}) };
        config.providers = mutate(config.providers || []);
        const username = req.session?.user?.username || 'system';
        await PluginModel.upsert('auth-oauth', config, username);
        await OauthProviderModel.invalidateCachedProviders();
        return config;
    }

    /**
     * POST /api/1/auth-oauth/admin/providers
     * Create a new provider config. Body is the stored provider shape (design doc §8) plus an
     * optional plaintext `clientSecret`, which is encrypted immediately (never persisted in
     * plaintext) - see OauthProviderModel.setClientSecret().
     */
    static async apiAdminProvidersCreate(req, res) {
        const body = req.body || {};
        global.LogController.logRequest(req, 'oauthAuth.apiAdminProvidersCreate', body.id || '');
        try {
            const validationError = OauthAuthController._validateProviderInput(body, { requireId: true });
            if (validationError) {
                global.LogController.logError(req, 'oauthAuth.apiAdminProvidersCreate', `error: ${validationError}`);
                return global.CommonUtils.sendError(req, res, 400, validationError, 'VALIDATION_ERROR');
            }

            const existing = await OauthProviderModel.getProviderById(body.id);
            if (existing) {
                global.LogController.logError(req, 'oauthAuth.apiAdminProvidersCreate', `error: provider id already exists: ${body.id}`);
                return global.CommonUtils.sendError(req, res, 400, `Provider id '${body.id}' already exists`, 'VALIDATION_ERROR');
            }

            const { clientSecret, ...entry } = body;
            if (entry.icon !== undefined) {
                entry.icon = sanitizeIcon(entry.icon);
            }
            if (clientSecret) {
                entry.clientSecretRef = await OauthProviderModel.setClientSecret(body.id, clientSecret);
            }

            await OauthAuthController._saveProviders(req, providers => [...providers, entry]);
            global.LogController.logInfo(req, 'oauthAuth.apiAdminProvidersCreate', `success: created provider ${body.id}`);
            return res.json({ success: true, data: entry });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiAdminProvidersCreate', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to create provider', 'INTERNAL_ERROR');
        }
    }

    /**
     * PUT /api/1/auth-oauth/admin/providers/:id
     * Update an existing provider config. Omitting `clientSecret` from the body keeps the
     * previously-stored secret (its `clientSecretRef`) untouched; a non-empty `clientSecret`
     * re-encrypts and replaces it.
     */
    static async apiAdminProvidersUpdate(req, res) {
        const providerId = req.params.id;
        const body = req.body || {};
        global.LogController.logRequest(req, 'oauthAuth.apiAdminProvidersUpdate', providerId);
        try {
            const validationError = OauthAuthController._validateProviderInput(body, { requireId: false });
            if (validationError) {
                global.LogController.logError(req, 'oauthAuth.apiAdminProvidersUpdate', `error: ${validationError}`);
                return global.CommonUtils.sendError(req, res, 400, validationError, 'VALIDATION_ERROR');
            }

            const existing = await OauthProviderModel.getProviderById(providerId);
            if (!existing) {
                global.LogController.logError(req, 'oauthAuth.apiAdminProvidersUpdate', `error: provider not found: ${providerId}`);
                return global.CommonUtils.sendError(req, res, 404, `Provider '${providerId}' not found`, 'NOT_FOUND');
            }

            const { clientSecret, ...fields } = body;
            if (fields.icon !== undefined) {
                fields.icon = sanitizeIcon(fields.icon);
            }
            const updatedEntry = { ...existing, ...fields, id: providerId };
            if (clientSecret) {
                updatedEntry.clientSecretRef = await OauthProviderModel.setClientSecret(providerId, clientSecret);
            }

            await OauthAuthController._saveProviders(req,
                providers => providers.map(p => (p.id === providerId ? updatedEntry : p)));
            global.LogController.logInfo(req, 'oauthAuth.apiAdminProvidersUpdate', `success: updated provider ${providerId}`);
            return res.json({ success: true, data: updatedEntry });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiAdminProvidersUpdate', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to update provider', 'INTERNAL_ERROR');
        }
    }

    /**
     * DELETE /api/1/auth-oauth/admin/providers/:id
     * Remove a provider config and its encrypted secret (if any). Does not touch any user's
     * `oauth.{provider}` link block - those become orphaned but harmless (login/init 404s).
     */
    static async apiAdminProvidersDelete(req, res) {
        const providerId = req.params.id;
        global.LogController.logRequest(req, 'oauthAuth.apiAdminProvidersDelete', providerId);
        try {
            const existing = await OauthProviderModel.getProviderById(providerId);
            if (!existing) {
                global.LogController.logError(req, 'oauthAuth.apiAdminProvidersDelete', `error: provider not found: ${providerId}`);
                return global.CommonUtils.sendError(req, res, 404, `Provider '${providerId}' not found`, 'NOT_FOUND');
            }

            await OauthAuthController._saveProviders(req, providers => providers.filter(p => p.id !== providerId));
            await OauthProviderModel.deleteClientSecret(providerId);
            global.LogController.logInfo(req, 'oauthAuth.apiAdminProvidersDelete', `success: deleted provider ${providerId}`);
            return res.json({ success: true });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiAdminProvidersDelete', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to delete provider', 'INTERNAL_ERROR');
        }
    }

    /**
     * POST /api/1/auth-oauth/admin/providers/:id/test
     * Force a fresh OIDC discovery (or validate manual OAuth2 endpoints) and return the resolved
     * server metadata, so the admin gets immediate feedback that the config is reachable/correct
     * (design doc "UI Components" §3, manual test matrix #19).
     */
    static async apiAdminProvidersTest(req, res) {
        const providerId = req.params.id;
        global.LogController.logRequest(req, 'oauthAuth.apiAdminProvidersTest', providerId);
        try {
            const providerWithSecret = await OauthProviderModel.getProviderWithSecret(providerId);
            if (!providerWithSecret) {
                global.LogController.logError(req, 'oauthAuth.apiAdminProvidersTest', `error: provider not found: ${providerId}`);
                return global.CommonUtils.sendError(req, res, 404, `Provider '${providerId}' not found`, 'NOT_FOUND');
            }

            oauthClient.invalidateConfiguration(providerWithSecret);
            const config = await oauthClient.getConfiguration(providerWithSecret);
            const metadata = config.serverMetadata();

            global.LogController.logInfo(req, 'oauthAuth.apiAdminProvidersTest', `success: connection verified for provider ${providerId}`);
            return res.json({
                success: true,
                data: {
                    issuer: metadata.issuer,
                    authorizationEndpoint: metadata.authorization_endpoint,
                    tokenEndpoint: metadata.token_endpoint,
                    userinfoEndpoint: metadata.userinfo_endpoint,
                    jwksUri: metadata.jwks_uri
                }
            });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiAdminProvidersTest', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 400,
                'Connection test failed - check the provider configuration', 'PROVIDER_TEST_FAILED');
        }
    }

    /**
     * GET /api/1/auth-oauth/init/:provider
     * Start the Authorization Code + PKCE flow: generate state/nonce/PKCE, stash them in
     * req.session.oauthPending, and 302 to the provider's authorization endpoint.
     */
    static async apiInit(req, res) {
        const providerId = req.params.provider;
        global.LogController.logRequest(req, 'oauthAuth.apiInit', providerId);

        const rateLimit = await global.RedisManager.cacheCheckRateLimit(
            'controller:auth-oauth:rateLimit:init', getClientIp(req),
            { limit: RATE_LIMIT_MAX_REQUESTS, windowSeconds: RATE_LIMIT_WINDOW_SECONDS });
        if (!rateLimit.allowed) {
            global.LogController.logError(req, 'oauthAuth.apiInit', `error: rate limit exceeded for provider ${providerId}`);
            return OauthAuthController.redirectToError(req, res, 'RATE_LIMITED');
        }

        try {
            const result = await OauthAuthController._startAuthorizationFlow(req, providerId, 'login', {
                redirectUrl: req.query.redirect || '/'
            });
            if (result.error) {
                global.LogController.logError(req, 'oauthAuth.apiInit', `error: ${result.error} for provider ${providerId}`);
                return OauthAuthController.redirectToError(req, res, result.error);
            }

            global.LogController.logInfo(req, 'oauthAuth.apiInit', `success: redirecting to provider ${providerId}`);
            return res.redirect(result.authUrl.href);
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiInit', `error: ${error.message}`);
            return OauthAuthController.redirectToError(req, res, 'INTERNAL_ERROR');
        }
    }

    /**
     * Shared PKCE/state/nonce setup for apiInit ('login' mode) and apiLink ('link' mode): resolve
     * the provider, generate flow secrets, stash them (plus any caller-supplied extra pending
     * fields, e.g. `userId`/`redirectUrl`) in req.session.oauthPending, and build the
     * authorization URL to send the browser to.
     * @returns {Promise<{ authUrl: URL }|{ error: string }>}
     */
    static async _startAuthorizationFlow(req, providerId, mode, extraPendingFields = {}) {
        const providerWithSecret = await OauthProviderModel.getProviderWithSecret(providerId);
        if (!providerWithSecret || !providerWithSecret.enabled) {
            return { error: 'PROVIDER_ERROR' };
        }

        const { codeVerifier, codeChallenge } = await oauthClient.generatePkce();
        const state = oauthClient.generateState();
        const nonce = providerWithSecret.type === 'oidc' ? oauthClient.generateNonce() : null;

        req.session.oauthPending = {
            provider: providerId,
            mode,
            state,
            nonce,
            codeVerifier,
            createdAt: Date.now(),
            ...extraPendingFields
        };

        const config = await oauthClient.getConfiguration(providerWithSecret);
        const authUrl = oauthClient.buildAuthorizationUrl(config, {
            redirectUri: computeRedirectUri(req, providerId),
            scopes: providerWithSecret.scopes,
            state,
            codeChallenge,
            nonce
        });

        return { authUrl };
    }

    /**
     * GET /api/1/auth-oauth/callback/:provider
     * Finish the flow: validate state/PKCE/nonce, exchange the code for tokens, verify the ID
     * token (OIDC) or fetch+map userinfo (custom OAuth2), resolve the local user, then hand off
     * to AuthController.completeExternalAuth() (W-195) for session creation / multi-step
     * continuation (e.g. MFA).
     */
    static async apiCallback(req, res) {
        const providerId = req.params.provider;
        global.LogController.logRequest(req, 'oauthAuth.apiCallback', providerId);

        const rateLimit = await global.RedisManager.cacheCheckRateLimit(
            'controller:auth-oauth:rateLimit:callback', getClientIp(req),
            { limit: RATE_LIMIT_MAX_REQUESTS, windowSeconds: RATE_LIMIT_WINDOW_SECONDS });
        if (!rateLimit.allowed) {
            global.LogController.logError(req, 'oauthAuth.apiCallback', `error: rate limit exceeded for provider ${providerId}`);
            return OauthAuthController.redirectToError(req, res, 'RATE_LIMITED');
        }

        const pending = req.session.oauthPending;

        try {
            if (req.query.error) {
                global.LogController.logError(req, 'oauthAuth.apiCallback',
                    `error: provider returned error for ${providerId}: ${req.query.error}`);
                delete req.session.oauthPending;
                return OauthAuthController.redirectToError(req, res, 'PROVIDER_ERROR');
            }

            if (!pending || pending.provider !== providerId || (Date.now() - pending.createdAt) > PENDING_TIMEOUT_MS) {
                global.LogController.logError(req, 'oauthAuth.apiCallback',
                    `error: missing/mismatched/expired oauthPending for provider ${providerId}`);
                delete req.session.oauthPending;
                return OauthAuthController.redirectToError(req, res, 'STATE_MISMATCH');
            }

            const providerWithSecret = await OauthProviderModel.getProviderWithSecret(providerId);
            if (!providerWithSecret || !providerWithSecret.enabled) {
                delete req.session.oauthPending;
                global.LogController.logError(req, 'oauthAuth.apiCallback', `error: provider ${providerId} no longer configured/enabled`);
                return OauthAuthController.redirectToError(req, res, 'PROVIDER_ERROR');
            }

            const config = await oauthClient.getConfiguration(providerWithSecret);
            const currentUrl = new URL(req.protocol + '://' + req.get('host') + req.originalUrl);

            // openid-client validates `state` (against expectedState) and, when a nonce was sent,
            // the ID token's nonce claim - satisfies the CSRF/replay checks in the design doc's
            // Security Requirements without us re-implementing timing-safe comparisons by hand.
            const { tokens, claims } = await oauthClient.exchangeCodeForTokens(config, currentUrl, {
                codeVerifier: pending.codeVerifier,
                expectedState: pending.state,
                expectedNonce: pending.nonce || undefined
            });
            delete req.session.oauthPending;

            const identity = await OauthAuthController._resolveIdentity(config, providerWithSecret, tokens, claims);
            if (!identity?.sub) {
                global.LogController.logError(req, 'oauthAuth.apiCallback', `error: provider ${providerId} returned no subject identifier`);
                return OauthAuthController.redirectToError(req, res, 'PROVIDER_ERROR');
            }

            if (pending.mode === 'link') {
                return OauthAuthController._handleLinkCallback(req, res, pending, providerId, identity);
            }
            return OauthAuthController._handleLoginCallback(req, res, pending, providerId, providerWithSecret, identity);
        } catch (error) {
            delete req.session.oauthPending;
            global.LogController.logError(req, 'oauthAuth.apiCallback', `error: ${error.message}`);
            return OauthAuthController.redirectToError(req, res, 'INTERNAL_ERROR');
        }
    }

    /** apiCallback's 'login' branch (apiInit-initiated): resolve/find/create a user and log them in. */
    static async _handleLoginCallback(req, res, pending, providerId, providerWithSecret, identity) {
        const resolution = await OauthAuthController._resolveUser(providerId, providerWithSecret, identity);
        if (resolution.error) {
            global.LogController.logError(req, 'oauthAuth.apiCallback',
                `error: ${resolution.error} for provider ${providerId} (sub=${identity.sub})`);
            return OauthAuthController.redirectToError(req, res, resolution.error);
        }

        const user = resolution.user;
        // No implicit framework-side gate on user.status inside completeExternalAuth() (W-195) -
        // the plugin's own callback handler must check it explicitly, before calling it (design
        // doc §7 "Interaction with status: 'pending'"). Mirrors the existing locked/disabled
        // convention used elsewhere in auth.js.
        if (user.status === 'locked') {
            global.LogController.logError(req, 'oauthAuth.apiCallback', `error: account locked for user ${user.username}`);
            return OauthAuthController.redirectToError(req, res, 'ACCOUNT_LOCKED');
        }
        if (user.status === 'disabled') {
            global.LogController.logError(req, 'oauthAuth.apiCallback', `error: account disabled for user ${user.username}`);
            return OauthAuthController.redirectToError(req, res, 'ACCOUNT_DISABLED');
        }
        if (user.status === 'pending') {
            global.LogController.logError(req, 'oauthAuth.apiCallback', `error: account pending approval for user ${user.username}`);
            return OauthAuthController.redirectToError(req, res, 'ACCOUNT_PENDING_APPROVAL');
        }

        // JIT-created users already have their oauth.{provider} block set at creation time
        // (_createJitUser) - re-recording it here is a harmless no-op ($set of the same shape)
        // and keeps this the single place that maintains linkedAt/lastLoginAt for every path.
        await OauthAuthController._recordProviderLink(user, providerId, identity, resolution.isNewLink);

        global.LogController.logInfo(req, 'oauthAuth.apiCallback',
            `success: user ${user.username} authenticated via ${providerId} (sub=${identity.sub})`);
        return AuthController.completeExternalAuth(req, res, user, 'oauth', pending.redirectUrl);
    }

    /**
     * apiCallback's 'link' branch (apiLink-initiated): attach this identity to the *already
     * logged-in* user who started the flow - no linking-strategy lookup, no session creation.
     */
    static async _handleLinkCallback(req, res, pending, providerId, identity) {
        if (!req.session.user?.id || req.session.user.id !== pending.userId) {
            global.LogController.logError(req, 'oauthAuth.apiCallback',
                'error: link flow requires the initiating user session to still be authenticated');
            return OauthAuthController.redirectToError(req, res, 'STATE_MISMATCH');
        }

        const existingLinkOwner = await OauthAuthModel.findUserByProviderSub(providerId, identity.sub);
        if (existingLinkOwner && existingLinkOwner._id.toString() !== pending.userId) {
            global.LogController.logError(req, 'oauthAuth.apiCallback',
                `error: sub ${identity.sub} for provider ${providerId} already linked to a different account`);
            return OauthAuthController.redirectToError(req, res, 'ALREADY_LINKED_TO_ANOTHER_ACCOUNT');
        }

        const user = await UserModel.findById(pending.userId);
        if (!user) {
            global.LogController.logError(req, 'oauthAuth.apiCallback', `error: user ${pending.userId} no longer exists`);
            return OauthAuthController.redirectToError(req, res, 'INTERNAL_ERROR');
        }

        await OauthAuthController._recordProviderLink(user, providerId, identity, !existingLinkOwner);
        global.LogController.logInfo(req, 'oauthAuth.apiCallback',
            `success: linked provider ${providerId} to user ${user.username}`);
        return res.redirect(`${pending.redirectUrl || '/jpulse-plugins/auth-oauth.shtml'}?linked=1`);
    }

    /**
     * Normalize provider identity claims. OIDC providers (google/oidc presets) supply this
     * directly from the verified ID token. The custom OAuth2 preset has no ID token at all - we
     * fetch userinfo with the access token and map it through the admin-configured field mapping.
     * @returns {Promise<{ sub, email, emailVerified, name, picture, preferredUsername, iss }|null>}
     */
    static async _resolveIdentity(config, providerWithSecret, tokens, claims) {
        if (providerWithSecret.type === 'oidc' && claims) {
            return {
                sub: claims.sub,
                email: claims.email,
                emailVerified: claims.email_verified === true,
                name: claims.name,
                givenName: claims.given_name || null,
                familyName: claims.family_name || null,
                picture: claims.picture,
                preferredUsername: claims.preferred_username,
                iss: claims.iss
            };
        }

        // Custom OAuth2 preset (design doc §2): no ID token, no nonce - identity comes entirely
        // from the userinfo endpoint via the admin-configured field mapping.
        const userinfo = await oauthClient.fetchUserInfo(config, tokens.access_token);
        const mapped = mapUserinfoToClaims(userinfo, providerWithSecret.userinfoMapping);
        return {
            sub: mapped.sub != null ? String(mapped.sub) : undefined,
            email: mapped.email,
            // Custom OAuth2 providers have no equivalent of OIDC's email_verified claim - treated
            // as unverified by design (design doc §7: "email_verified: true required for
            // link-by-email and JIT... never trust unverified emails for linking").
            emailVerified: false,
            name: mapped.name,
            givenName: null,
            familyName: null,
            picture: null,
            preferredUsername: null,
            iss: null
        };
    }

    /**
     * Resolve a local user for this identity, per the provider's linking strategy (design doc
     * §7): `sub-only` (existing users only, matched by provider sub), `link-by-email` (existing
     * users only, matched by verified email), or `jit-create` (matches by verified email like
     * link-by-email, but creates a new user via _createJitUser() instead of failing closed when
     * there's no existing user to link).
     * @returns {Promise<{ user: object, isNewLink: boolean }|{ error: string }>}
     */
    static async _resolveUser(providerId, providerWithSecret, identity) {
        const subMatches = await UserModel.find({ [`oauth.${providerId}.sub`]: identity.sub }, { limit: 1 });
        if (subMatches.length > 0) {
            return { user: subMatches[0], isNewLink: false };
        }

        const pluginDoc = await PluginModel.getByName('auth-oauth');
        const strategy = providerWithSecret.linkingStrategy || pluginDoc?.config?.defaultLinkingStrategy || 'link-by-email';

        if (strategy === 'link-by-email' || strategy === 'jit-create') {
            if (!identity.email) {
                return { error: 'USER_NOT_PROVISIONED' };
            }
            if (!identity.emailVerified) {
                return { error: 'EMAIL_NOT_VERIFIED_AT_PROVIDER' };
            }
            const emailMatches = await UserModel.find({ email: identity.email }, { limit: 2 });
            if (emailMatches.length > 1) {
                return { error: 'AMBIGUOUS_EMAIL_MATCH' };
            }
            if (emailMatches.length === 1) {
                return { user: emailMatches[0], isNewLink: true };
            }
            // No existing user by sub or email. link-by-email fails closed (existing users only,
            // by design); jit-create instead provisions a new one (design doc §10 Stage A).
            if (strategy === 'jit-create') {
                return OauthAuthController._createJitUser(providerId, providerWithSecret, identity, pluginDoc);
            }
        }

        // strategy === 'sub-only' with no match fails closed - no email fallback by design.
        return { error: 'USER_NOT_PROVISIONED' };
    }

    /**
     * jit-create: provision a brand-new local user from a best-effort extracted profile (design
     * doc §10 Stage A - see profileExtractor.js), writing only fields that already exist on
     * `UserModel.baseSchema` plus the `user.oauth._jit` sentinel (no framework schema changes
     * needed). If Stage A had to fall back to a placeholder for any `profileRequiredFields`
     * field, `onAuthGetSteps` below injects the `oauth-profile-complete` step (Stage B) into the
     * W-109 multi-step flow so the user confirms/fills it in before ever seeing it.
     * @returns {Promise<{ user: object, isNewLink: true }>}
     */
    static async _createJitUser(providerId, providerWithSecret, identity, pluginDoc) {
        const draft = extractProfile(identity);
        const roles = sanitizeJitRoles(providerWithSecret.jitRoles || pluginDoc?.config?.jitDefaultRoles);
        const status = providerWithSecret.jitStatus || pluginDoc?.config?.jitDefaultStatus || 'active';

        let username = draft.username;
        for (let attempt = 1; attempt <= 6; attempt++) {
            try {
                const newUser = await UserModel.create({
                    username,
                    email: identity.email,
                    // Never surfaced - nobody, including the plugin, retains the plaintext, so
                    // local login is impossible until the user explicitly sets a real password
                    // (design doc §7 - a blank/empty password is a known auth anti-pattern).
                    password: crypto.randomBytes(32).toString('hex'),
                    hasLocalPassword: false,
                    roles,
                    status,
                    profile: {
                        firstName: draft.firstName,
                        lastName: draft.lastName,
                        nickName: draft.nickName || '',
                        avatar: draft.picture || ''
                    },
                    oauth: {
                        _jit: {
                            createdAt: new Date(),
                            viaProvider: providerId,
                            placeholderFields: draft.placeholderFields,
                            profileCompletedAt: null
                        }
                    }
                });
                return { user: newUser, isNewLink: true };
            } catch (error) {
                if (/username already exists/i.test(error.message) && attempt < 6) {
                    username = `${draft.username}-${attempt + 1}`;
                    continue;
                }
                if (/email address already registered/i.test(error.message) || /duplicate key/i.test(error.message)) {
                    // Two JIT-eligible logins for a brand-new email raced each other (design doc
                    // §9 edge case) - the loser retries as a lookup instead of surfacing a 500.
                    const raced = await UserModel.find({ email: identity.email }, { limit: 1 });
                    if (raced.length > 0) {
                        return { user: raced[0], isNewLink: true };
                    }
                }
                throw error;
            }
        }
        throw new Error('Failed to allocate a unique username after multiple attempts');
    }

    /**
     * W-109 hook: inject the `oauth-profile-complete` step for jit-create users whose IdP didn't
     * provide all `profileRequiredFields` (design doc §10 Stage B). Gated entirely by the
     * `user.oauth._jit` sentinel written at creation time - never by re-inspecting
     * `profile.firstName`/`profile.lastName` for emptiness, since those are never empty
     * (schema-required, always populated with either a real or placeholder value). Existing
     * users linked via sub-only/link-by-email never have an `oauth._jit` block, so they never see
     * this prompt.
     * @param {object} context - { req, user, completedSteps, requiredSteps }
     */
    static async onAuthGetSteps(context) {
        const { req, user, requiredSteps } = context;
        try {
            const jit = user?.oauth?._jit;
            if (!jit || jit.profileCompletedAt) {
                return context;
            }
            const pluginDoc = await PluginModel.getByName('auth-oauth');
            const requiredFields = pluginDoc?.config?.profileRequiredFields ?? ['firstName', 'lastName'];
            const missing = (jit.placeholderFields || []).filter(f => requiredFields.includes(f));
            if (missing.length === 0) {
                return context;
            }

            requiredSteps.push({
                step: 'oauth-profile-complete',
                priority: 20, // before mfa-setup (100), after any tenant-select-style step (5)
                // 'page' is REQUIRED here, not just a browser-redirect nicety - login.shtml's
                // client-side handleNextStep() only has hardcoded routing for the framework's own
                // 'mfa'/'mfa-setup'/'email-verify' step names; this plugin-defined step needs its
                // own 'page' even in the pure-AJAX POST /api/1/auth/login flow.
                page: '/auth/oauth-profile-complete.shtml',
                data: {
                    missingFields: missing,
                    prefill: {
                        firstName: user.profile?.firstName || '',
                        lastName: user.profile?.lastName || '',
                        nickName: user.profile?.nickName || ''
                    }
                }
            });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.onAuthGetSteps', `error: ${error.message}`);
        }
        return context;
    }

    /**
     * W-109 hook: validate/save the `oauth-profile-complete` step submission, clearing the
     * `oauth._jit` placeholder sentinel so this step never fires again for this user.
     * @param {object} context - { req, user, step, stepData, pending, valid, error }
     */
    static async onAuthValidateStep(context) {
        const { req, step, stepData, user } = context;
        if (step !== 'oauth-profile-complete') {
            return context;
        }

        try {
            const pluginDoc = await PluginModel.getByName('auth-oauth');
            const requiredFields = pluginDoc?.config?.profileRequiredFields ?? ['firstName', 'lastName'];
            const missingRequired = requiredFields.filter(f => !stepData?.[f]?.trim());
            if (missingRequired.length > 0) {
                context.valid = false;
                context.error = 'Please fill in all required fields';
                return context;
            }

            const updates = {};
            if (stepData.firstName?.trim()) updates['profile.firstName'] = stepData.firstName.trim();
            if (stepData.lastName?.trim()) updates['profile.lastName'] = stepData.lastName.trim();
            if (stepData.nickName?.trim()) updates['profile.nickName'] = stepData.nickName.trim();
            updates['oauth._jit.placeholderFields'] = [];
            updates['oauth._jit.profileCompletedAt'] = new Date();

            await UserModel.updateById(user._id, updates);
            context.valid = true;
            global.LogController.logInfo(req, 'oauthAuth.onAuthValidateStep',
                `success: profile completed for user ${user.username}`);
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.onAuthValidateStep', `error: ${error.message}`);
            context.valid = false;
            context.error = 'Failed to save your profile';
        }
        return context;
    }

    /**
     * GET /api/1/auth-oauth/profile-draft
     * Read-only helper for the oauth-profile-complete.shtml Stage B form: re-derives
     * `missingFields`/current profile values from `req.session.pendingAuth` (set by
     * AuthController.completeExternalAuth()/login() - never a plugin-owned session key) plus the
     * user's `oauth._jit` sentinel, the same way onAuthGetSteps() does. Actually submitting the
     * form goes through the shared POST /api/1/auth/login (design doc §10 - keeps the whole
     * authentication chain uniform), not a plugin-specific endpoint.
     */
    static async apiProfileDraft(req, res) {
        global.LogController.logRequest(req, 'oauthAuth.apiProfileDraft', '');
        try {
            const pending = req.session.pendingAuth;
            const expired = !pending || (Date.now() - pending.createdAt) > PENDING_TIMEOUT_MS;
            const wrongStep = pending && (!pending.requiredSteps?.includes('oauth-profile-complete')
                || pending.completedSteps?.includes('oauth-profile-complete'));
            if (expired || wrongStep) {
                return global.CommonUtils.sendError(req, res, 400,
                    'Your sign-in session has expired. Please sign in again.', 'STATE_MISMATCH');
            }

            const user = await UserModel.findById(pending.userId);
            const jit = user?.oauth?._jit;
            if (!user || !jit || jit.profileCompletedAt) {
                return global.CommonUtils.sendError(req, res, 400,
                    'Your sign-in session has expired. Please sign in again.', 'STATE_MISMATCH');
            }

            const pluginDoc = await PluginModel.getByName('auth-oauth');
            const requiredFields = pluginDoc?.config?.profileRequiredFields ?? ['firstName', 'lastName'];
            const missingFields = (jit.placeholderFields || []).filter(f => requiredFields.includes(f));

            return res.json({
                success: true,
                data: {
                    email: user.email,
                    missingFields,
                    firstName: user.profile?.firstName || '',
                    lastName: user.profile?.lastName || '',
                    nickName: user.profile?.nickName || ''
                }
            });
        } catch (error) {
            global.LogController.logError(req, 'oauthAuth.apiProfileDraft', `error: ${error.message}`);
            return global.CommonUtils.sendError(req, res, 500, 'Failed to load profile draft', 'INTERNAL_ERROR');
        }
    }

    /** Write/update the user's oauth.{provider} block (linkedAt on first link, lastLoginAt always). */
    static async _recordProviderLink(user, providerId, identity, isNewLink) {
        const now = new Date();
        const existingBlock = user.oauth?.[providerId];
        await UserModel.updateById(user._id, {
            [`oauth.${providerId}`]: {
                sub: identity.sub,
                email: identity.email || null,
                emailVerified: identity.emailVerified,
                name: identity.name || null,
                picture: identity.picture || null,
                preferredUsername: identity.preferredUsername || null,
                iss: identity.iss || null,
                linkedAt: existingBlock?.linkedAt || now,
                lastLoginAt: now
            }
        });
        void isNewLink; // reserved for future logging/metrics distinction between first-link and repeat login
    }
}

export default OauthAuthController;

// EOF plugins/auth-oauth/webapp/controller/oauthAuth.js
