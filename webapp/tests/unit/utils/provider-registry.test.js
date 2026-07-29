/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Tests / Unit / Utils / Provider Registry
 * @tagline         Unit tests for providerRegistry.js preset resolution
 * @description     Tests preset lookup, validation, and merging of preset defaults with
 *                   admin-configured provider overrides
 * @file            plugins/auth-oauth/webapp/tests/unit/utils/provider-registry.test.js
 * @version         1.0.0
 * @release         2026-07-29
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import { describe, test, expect } from '@jest/globals';
import { PROVIDER_PRESETS, getPreset, isValidPreset, resolveProviderConfig } from '../../../utils/providerRegistry.js';

describe('providerRegistry', () => {
    describe('getPreset / isValidPreset', () => {
        test('returns the google preset with expected OIDC defaults', () => {
            const preset = getPreset('google');
            expect(preset).toMatchObject({
                type: 'oidc',
                label: 'Google',
                discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
                scopes: ['openid', 'email', 'profile'],
                requiresClientSecret: true
            });
        });

        test('returns the generic oidc preset with no baked-in discoveryUrl', () => {
            const preset = getPreset('oidc');
            expect(preset.type).toBe('oidc');
            expect(preset.discoveryUrl).toBeUndefined();
        });

        test('returns the oauth2 preset', () => {
            const preset = getPreset('oauth2');
            expect(preset.type).toBe('oauth2');
            expect(preset.scopes).toEqual([]);
        });

        test('returns null for an unknown preset key', () => {
            expect(getPreset('does-not-exist')).toBeNull();
        });

        test('isValidPreset reflects registry contents', () => {
            expect(isValidPreset('google')).toBe(true);
            expect(isValidPreset('oidc')).toBe(true);
            expect(isValidPreset('oauth2')).toBe(true);
            expect(isValidPreset('saml')).toBe(false);
        });

        test('registry exposes exactly the three v1.0.0 presets', () => {
            expect(Object.keys(PROVIDER_PRESETS).sort()).toEqual(['google', 'oauth2', 'oidc']);
        });
    });

    describe('resolveProviderConfig', () => {
        test('merges preset defaults with a minimal stored provider entry', () => {
            const resolved = resolveProviderConfig({ id: 'google-corp', preset: 'google', enabled: true });

            expect(resolved.type).toBe('oidc');
            expect(resolved.discoveryUrl).toBe('https://accounts.google.com/.well-known/openid-configuration');
            expect(resolved.scopes).toEqual(['openid', 'email', 'profile']);
            expect(resolved.id).toBe('google-corp');
            expect(resolved.enabled).toBe(true);
        });

        test('stored fields override preset defaults (e.g. custom label/buttonColor)', () => {
            const resolved = resolveProviderConfig({
                id: 'google-corp',
                preset: 'google',
                label: 'Sign in with Corp Google',
                buttonColor: '#123456'
            });

            expect(resolved.label).toBe('Sign in with Corp Google');
            expect(resolved.buttonColor).toBe('#123456');
        });

        test('a non-empty stored scopes list overrides the preset default', () => {
            const resolved = resolveProviderConfig({
                id: 'okta-prod',
                preset: 'oidc',
                scopes: ['openid', 'email', 'groups']
            });

            expect(resolved.scopes).toEqual(['openid', 'email', 'groups']);
        });

        test('an empty stored scopes list falls back to the preset default', () => {
            const resolved = resolveProviderConfig({ id: 'okta-prod', preset: 'oidc', scopes: [] });
            expect(resolved.scopes).toEqual(['openid', 'email', 'profile']);
        });

        test('throws for a missing providerConfig', () => {
            expect(() => resolveProviderConfig(null)).toThrow();
            expect(() => resolveProviderConfig(undefined)).toThrow();
        });

        test('throws for an unknown preset key', () => {
            expect(() => resolveProviderConfig({ id: 'x', preset: 'not-a-preset' })).toThrow();
        });
    });
});

// EOF plugins/auth-oauth/webapp/tests/unit/utils/provider-registry.test.js
