/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Utils / Profile Extractor
 * @tagline         Stage A best-effort claim extraction for jit-create user provisioning
 * @description     Turns a resolved OAuth/OIDC identity (see oauthAuth.js _resolveIdentity()) into
 *                   a schema-conformant draft profile for jit-create user creation (design doc
 *                   §10 Stage A). `profile.firstName`/`profile.lastName` are required on
 *                   `UserModel.baseSchema`, so the fallback chain below always resolves to a
 *                   non-empty string - but `placeholderFields` separately records which fields
 *                   only got a placeholder, so Stage B (oauth-profile-complete step, see
 *                   oauthAuth.js onAuthGetSteps/onAuthValidateStep) knows what to actually ask
 *                   about. Checking "is the DB value empty" would never work here, since it's
 *                   never empty by construction.
 * @file            plugins/auth-oauth/webapp/utils/profileExtractor.js
 * @version         1.0.4
 * @release         2026-09-30
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

/**
 * Best-effort extraction of a schema-conformant draft profile from resolved identity claims.
 * @param {object} identity - Resolved identity (see oauthAuth.js _resolveIdentity()):
 *        { sub, email, name, givenName, familyName, preferredUsername, picture }
 * @returns {{ firstName: string, lastName: string, nickName: string|null, picture: string|null,
 *             username: string, placeholderFields: string[] }}
 */
export function extractProfile(identity) {
    const claims = identity || {};
    const placeholderFields = [];
    const nameParts = claims.name?.trim() ? claims.name.trim().split(/\s+/) : [];

    let firstName;
    if (claims.givenName) {
        firstName = claims.givenName;
    } else if (nameParts.length > 1) {
        firstName = nameParts.slice(0, -1).join(' '); // "Jane Marie Doe" -> "Jane Marie"
    } else if (claims.preferredUsername?.includes('.')) {
        firstName = claims.preferredUsername.split('.')[0]; // "jane.doe" -> "jane"
    } else {
        firstName = claims.name?.trim() || claims.preferredUsername || claims.email?.split('@')[0] || claims.sub;
        placeholderFields.push('firstName'); // real value unknown - Stage B will ask
    }

    let lastName;
    if (claims.familyName) {
        lastName = claims.familyName;
    } else if (nameParts.length > 1) {
        lastName = nameParts[nameParts.length - 1]; // "Jane Marie Doe" -> "Doe"
    } else if (claims.preferredUsername?.includes('.')) {
        lastName = claims.preferredUsername.split('.').slice(1).join(' ');
    } else {
        lastName = '-'; // schema-valid placeholder; overwritten by Stage B before it's ever displayed
        placeholderFields.push('lastName');
    }

    return {
        firstName,
        lastName,
        nickName: claims.nickname || claims.givenName || claims.preferredUsername || null,
        picture: claims.picture || null,
        username: sanitizeUsername(
            claims.preferredUsername || (claims.email ? claims.email.split('@')[0] : '') || claims.sub || 'user'
        ),
        placeholderFields
    };
}

/** Constrain a claim-derived username candidate to the schema's allowed charset (`[a-z0-9_.-]+`). */
function sanitizeUsername(candidate) {
    const sanitized = String(candidate).toLowerCase().replace(/[^a-z0-9_.-]/g, '');
    return sanitized || 'user';
}

// EOF plugins/auth-oauth/webapp/utils/profileExtractor.js
