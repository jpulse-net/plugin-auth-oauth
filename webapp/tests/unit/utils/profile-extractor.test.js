/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Tests / Unit / Utils / Profile Extractor
 * @tagline         Unit tests for profileExtractor.extractProfile
 * @description     Covers the design doc §10 Stage A extraction matrix: given_name/family_name
 *                   present, only full `name` present (split heuristic), preferred_username with
 *                   a dot (GitHub-style), and no usable name claims at all (schema-valid
 *                   placeholder + placeholderFields tracking).
 * @file            plugins/auth-oauth/webapp/tests/unit/utils/profile-extractor.test.js
 * @version         1.0.4
 * @release         2026-09-30
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import { describe, test, expect } from '@jest/globals';
import { extractProfile } from '../../../utils/profileExtractor.js';

describe('profileExtractor.extractProfile', () => {
    test('uses given_name/family_name directly when present (no placeholders)', () => {
        const result = extractProfile({
            sub: 'sub-1', email: 'jane@example.com', name: 'Jane Doe',
            givenName: 'Jane', familyName: 'Doe', preferredUsername: null
        });

        expect(result).toEqual({
            firstName: 'Jane',
            lastName: 'Doe',
            nickName: 'Jane',
            picture: null,
            username: 'jane',
            placeholderFields: []
        });
    });

    test('splits a full name heuristically when given_name/family_name are missing', () => {
        const result = extractProfile({ sub: 'sub-2', email: 'jane@example.com', name: 'Jane Marie Doe' });

        expect(result.firstName).toBe('Jane Marie');
        expect(result.lastName).toBe('Doe');
        expect(result.placeholderFields).toEqual([]);
    });

    test('splits a dotted preferred_username when no name claim is available', () => {
        const result = extractProfile({ sub: 'sub-3', email: 'jane@example.com', preferredUsername: 'jane.doe' });

        expect(result.firstName).toBe('jane');
        expect(result.lastName).toBe('doe');
        expect(result.placeholderFields).toEqual([]);
        expect(result.username).toBe('jane.doe');
    });

    test('falls back to schema-valid placeholders and records placeholderFields when no name claims exist at all', () => {
        const result = extractProfile({ sub: 'sub-4', email: 'jane@example.com' });

        expect(result.firstName).toBe('jane'); // email local-part fallback - still a placeholder (real value unknown)
        expect(result.lastName).toBe('-');     // schema-valid placeholder
        expect(result.placeholderFields).toEqual(['firstName', 'lastName']);
    });

    test('falls back to sub for firstName when there is no name, preferred_username, or email', () => {
        const result = extractProfile({ sub: 'sub-5' });

        expect(result.firstName).toBe('sub-5');
        expect(result.lastName).toBe('-');
        expect(result.placeholderFields).toEqual(['firstName', 'lastName']);
        expect(result.username).toBe('sub-5');
    });

    test('sanitizes the derived username to the schema charset [a-z0-9_.-]+', () => {
        const result = extractProfile({ sub: 'sub-6', email: 'Jane+Test@Example.com' });

        expect(result.username).toBe('janetest');
    });

    test('prefers nickname claim, then given_name, then preferred_username for nickName', () => {
        expect(extractProfile({ sub: 's', nickname: 'JD' }).nickName).toBe('JD');
        expect(extractProfile({ sub: 's', givenName: 'Jane' }).nickName).toBe('Jane');
        expect(extractProfile({ sub: 's', preferredUsername: 'jdoe' }).nickName).toBe('jdoe');
        expect(extractProfile({ sub: 's' }).nickName).toBeNull();
    });

    test('passes through the picture claim, defaulting to null', () => {
        expect(extractProfile({ sub: 's', picture: 'https://example.com/pic.png' }).picture).toBe('https://example.com/pic.png');
        expect(extractProfile({ sub: 's' }).picture).toBeNull();
    });
});

// EOF plugins/auth-oauth/webapp/tests/unit/utils/profile-extractor.test.js
