/**
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / Tests / Unit / View / Provider Renderer
 * @tagline         Unit tests for the "Identity Providers" custom config renderer
 * @description     Drives view/jpulse-common.js's renderProviders() in a JSDOM document with a
 *                   stubbed jPulse global, covering the parts that are easy to get subtly wrong:
 *                   live-binding into the in-memory array (there is no per-row Save button), the
 *                   preset switch and its effect on which endpoint fields apply, "blank means
 *                   inherit the preset default", and attribute-safe escaping (an SVG icon contains
 *                   double quotes, so a text-node escaper truncates it - and lets a crafted label
 *                   break out of value="..."). JSDOM is constructed by hand rather than via
 *                   testEnvironment: jsdom, which isn't installed - only the `jsdom` package is.
 * @file            plugins/auth-oauth/webapp/tests/unit/view/provider-renderer.test.js
 * @version         1.0.0
 * @release         2026-07-31
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { JSDOM } from 'jsdom';
import { getPreset } from '../../../utils/providerRegistry.js';

const RENDERER_PATH = path.resolve(__dirname, '../../../view/jpulse-common.js');
const RENDERER_SOURCE = fs.readFileSync(RENDERER_PATH, 'utf8');

describe('auth-oauth provider config renderer', () => {
    let window;
    let container;
    let ctx;
    let reported; // last value handed to ctx.onChange, deep-copied like the framework's snapshot

    /** Mount the renderer on a fresh document with the initial provider list. */
    function mount(initialProviders = [], options = {}) {
        const dom = new JSDOM('<!doctype html><html><body><div id="mount"></div></body></html>',
            { url: 'https://dev.example.com', runScripts: 'outside-only' });
        window = dom.window;
        window.jPulse = {
            string: {
                escapeHtml: (text) => {
                    const div = window.document.createElement('div');
                    div.textContent = text;
                    return div.innerHTML;
                }
            },
            UI: {
                toast: { show: jest.fn() },
                confirmDialog: jest.fn(async () => ({ confirmed: true })),
                // Minimal stand-in for the real jpSelect widget: wraps the <select> in
                // [data-jpselect-wrapper] and appends a dropdown "portal" to <body>, mirroring the
                // two DOM facts the renderer's cleanup logic (destroyJitRolesWidget) depends on -
                // without reimplementing the widget's actual dropdown/search/keyboard behavior,
                // which is the framework's own test suite's responsibility, not this plugin's.
                input: {
                    jpSelect: {
                        init: jest.fn((select) => {
                            if (select.dataset.jpselectInited) {
                                return;
                            }
                            select.dataset.jpselectInited = '1';
                            const wrap = window.document.createElement('div');
                            wrap.setAttribute('data-jpselect-wrapper', '1');
                            select.parentNode.insertBefore(wrap, select);
                            wrap.appendChild(select);
                            const dropdown = window.document.createElement('div');
                            dropdown.className = 'jp-jpselect-dropdown-stub';
                            window.document.body.appendChild(dropdown);
                            wrap._jpSelectDropdown = dropdown;
                        })
                    }
                }
            },
            api: {
                post: jest.fn(async () => ({ success: true, data: { issuer: 'https://accounts.google.com' } })),
                // /api/1/auth-oauth/admin/assignable-roles already excludes this site's
                // admin-equivalent roles server-side, so the default fixture never includes
                // 'admin'/'root' - a test that needs to prove the client doesn't second-guess
                // that filtering can still pass a `roles` option including them.
                get: jest.fn(async () => {
                    if (options.rolesFetchFails) {
                        throw new Error('network error');
                    }
                    return { success: true, data: { roles: options.roles || ['user'] } };
                })
            },
            // Real jPulse.schemaForm.register is a framework file this suite doesn't load; a bare
            // stub is enough since the renderer only calls it once at file-eval time to register
            // the "JIT: Default Roles" loadOptions handler, which this suite doesn't exercise.
            schemaForm: { register: jest.fn() }
        };
        window.eval(RENDERER_SOURCE);

        container = window.document.getElementById('mount');
        reported = null;
        ctx = {
            container,
            value: initialProviders,
            // The framework's onChange does JSON.stringify into a hidden field, i.e. it snapshots
            // immediately - mirror that so a later mutation can't silently "fix" a stale report.
            onChange: jest.fn((value) => { reported = JSON.parse(JSON.stringify(value)); }),
            disabled: !!options.disabled
        };
        window.jPulse.plugins.authOauth.renderProviders(ctx);
    }

    const q = (selector) => container.querySelector(selector);
    const all = (selector) => Array.from(container.querySelectorAll(selector));
    const tableText = () => container.querySelector('.plg-oauth-table tbody').textContent;

    /** Set an input's value and fire the event the renderer listens for. */
    function type(selector, value) {
        const el = q(selector);
        if (el.type === 'checkbox') {
            el.checked = value;
        } else {
            el.value = value;
        }
        const eventName = (el.tagName === 'SELECT' || el.type === 'checkbox' || el.type === 'color') ? 'change' : 'input';
        el.dispatchEvent(new window.Event(eventName, { bubbles: true }));
    }

    beforeEach(() => {
        mount();
    });

    describe('live binding (no per-row Save button)', () => {
        test('typing a field reports the whole array immediately', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'google-corp');

            expect(reported).toHaveLength(1);
            expect(reported[0].id).toBe('google-corp');
        });

        test('repaints the table as you type, without disturbing the open form', () => {
            q('.plg-oauth-add-btn').click();
            const idField = q('.plg-f-id');
            type('.plg-f-id', 'google-corp');

            expect(tableText()).toContain('google-corp');
            expect(q('.plg-f-id')).toBe(idField); // same node - focus and caret survive
        });

        test('keeps the redirect URI preview in step with the id being typed', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'okta-prod');

            expect(q('.plg-f-redirectUri').value)
                .toBe('https://dev.example.com/api/1/auth-oauth/callback/okta-prod');
        });

        test('does not alias ctx.value - the page\'s own config object stays untouched', () => {
            const original = [{ id: 'google-corp', preset: 'google', label: 'Google', enabled: true, order: 10 }];
            mount(original);
            q('.plg-oauth-edit-btn').click();
            type('.plg-f-label', 'Renamed');

            expect(reported[0].label).toBe('Renamed');
            expect(original[0].label).toBe('Google');
        });
    });

    describe('preset switching', () => {
        test('changing the preset sticks, and swaps in that preset\'s endpoint fields', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-preset', 'oidc');

            expect(reported[0].preset).toBe('oidc');
            expect(q('.plg-f-preset').value).toBe('oidc');
            expect(q('.plg-f-discoveryUrl')).not.toBeNull();
        });

        test('drops endpoint config the newly chosen preset does not use', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-preset', 'oidc');
            type('.plg-f-discoveryUrl', 'https://okta.example.com/.well-known/openid-configuration');
            expect(reported[0].discoveryUrl).toContain('okta.example.com');

            type('.plg-f-preset', 'google'); // google brings its own discovery URL

            expect(reported[0].discoveryUrl).toBeUndefined();
            expect(q('.plg-f-discoveryUrl')).toBeNull();
        });

        test('shows a tenant-specific discovery URL placeholder for the microsoft preset', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-preset', 'microsoft');

            expect(q('.plg-f-discoveryUrl')).not.toBeNull();
            expect(q('.plg-f-discoveryUrl').placeholder).toContain('login.microsoftonline.com');
        });

        test('shows the manual endpoint fields for the oauth2 preset only', () => {
            q('.plg-oauth-add-btn').click();
            expect(q('.plg-f-authorizeUrl')).toBeNull();

            type('.plg-f-preset', 'oauth2');
            expect(q('.plg-f-authorizeUrl')).not.toBeNull();
            expect(q('.plg-f-userinfoMapping')).not.toBeNull();

            type('.plg-f-userinfoMapping', '{"sub":"user_id"}');
            expect(reported[0].userinfoMapping).toEqual({ sub: 'user_id' });
        });

        test('keeps the last valid userinfo mapping while the JSON is mid-edit', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'custom-idp'); // the missing-id error would otherwise claim the slot
            type('.plg-f-preset', 'oauth2');
            type('.plg-f-userinfoMapping', '{"sub":"user_id"}');
            type('.plg-f-userinfoMapping', '{"sub":"user_i');

            expect(reported[0].userinfoMapping).toEqual({ sub: 'user_id' });
            expect(q('.plg-oauth-form-error').textContent).toMatch(/not valid JSON yet/);
        });

        test('lets an untouched button color follow the preset instead of freezing', () => {
            q('.plg-oauth-add-btn').click();
            expect(q('.plg-f-buttonColor').value).toBe('#4285f4'); // Google brand color

            type('.plg-f-preset', 'oidc');

            expect(q('.plg-f-buttonColor').value).toBe('#7f8fa6');
            expect(reported[0].buttonColor).toBeUndefined();
        });

        test('keeps a deliberately chosen button color across a preset change', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-buttonColor', '#ff0000');
            type('.plg-f-preset', 'oidc');

            expect(reported[0].buttonColor).toBe('#ff0000');
        });
    });

    describe('blank means "inherit the preset default"', () => {
        test('stores no label/icon key at all when those fields are left empty', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'google-corp');

            expect(reported[0]).not.toHaveProperty('label');
            expect(reported[0]).not.toHaveProperty('icon');
        });

        test('offers the preset\'s label as a placeholder, and an emoji preset\'s icon as-is', () => {
            mount([{ id: 'okta-corp', preset: 'oidc', enabled: true, order: 10 }]);
            q('.plg-oauth-edit-btn').click();

            expect(q('.plg-f-label').placeholder).toBe('OIDC Provider');
            expect(q('.plg-f-icon').placeholder).toBe('🔐');
        });

        test('describes a markup preset icon in the placeholder instead of showing raw SVG', () => {
            q('.plg-oauth-add-btn').click(); // google is the default preset for a new row

            expect(q('.plg-f-icon').placeholder).toBe('(Google logo)');
        });

        test('shows the inherited label muted in the table', () => {
            mount([{ id: 'google-corp', preset: 'google', enabled: true, order: 10 }]);

            expect(container.querySelector('.plg-oauth-table tbody .jp-text-muted').textContent).toBe('Google');
        });

        test('previews the inherited preset icon (the Google mark) in the table', () => {
            mount([{ id: 'google-corp', preset: 'google', enabled: true, order: 10 }]);

            const preview = container.querySelector('.plg-oauth-table tbody .plg-oauth-icon-preview');
            expect(preview.tagName).toBe('IMG');
            expect(decodeURIComponent(preview.src.replace(/^data:image\/svg\+xml;charset=utf-8,/, '')))
                .toBe(getPreset('google').icon);
        });
    });

    describe('icon preview in the table', () => {
        test('renders an emoji icon as text', () => {
            mount([{ id: 'corp', preset: 'oidc', icon: '🏢', enabled: true, order: 10 }]);

            const preview = container.querySelector('.plg-oauth-icon-preview');
            expect(preview.tagName).toBe('SPAN');
            expect(preview.textContent).toBe('🏢');
        });

        test('renders an SVG icon through an inert img data URL, never as live DOM', () => {
            const svg = '<svg viewBox="0 0 24 24"><path d="M1 1"/></svg>';
            mount([{ id: 'corp', preset: 'oidc', icon: svg, enabled: true, order: 10 }]);

            const preview = container.querySelector('.plg-oauth-icon-preview');
            expect(preview.tagName).toBe('IMG');
            // xmlns is required for SVG behind an <img>, and is added when the paste omits it
            expect(preview.getAttribute('src')).toBe('data:image/svg+xml;charset=utf-8,' +
                encodeURIComponent(svg.replace('<svg', '<svg xmlns="http://www.w3.org/2000/svg"')));
            // The unsaved value has not been through the server's sanitizer yet, so it must not
            // become real markup in the admin's own page.
            expect(container.querySelector('.plg-oauth-table tbody svg')).toBeNull();
        });

        test('keeps a script-bearing draft icon out of the DOM', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'corp');
            type('.plg-f-icon', '<svg onload="window.pwned=1"><script>window.pwned=1<\/script></svg>');

            expect(container.querySelector('.plg-oauth-table tbody script')).toBeNull();
            expect(container.querySelector('.plg-oauth-table tbody svg')).toBeNull();
            expect(window.pwned).toBeUndefined();
            expect(container.querySelector('.plg-oauth-icon-preview').tagName).toBe('IMG');
        });

        test('leaves an existing xmlns alone', () => {
            const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><path d="M1 1"/></svg>';
            mount([{ id: 'corp', preset: 'oidc', icon: svg, enabled: true, order: 10 }]);

            expect(container.querySelector('.plg-oauth-icon-preview').getAttribute('src'))
                .toBe('data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg));
        });

        test('restores viewBox casing the sanitizer lowercased, so a saved icon does not preview tiny/mis-scaled', () => {
            // CommonUtils.sanitizeHtml() lowercases every attribute name it re-serializes, so a
            // provider that's already been through the server's sanitizeIcon() comes back with
            // "viewbox", not "viewBox" - exactly what a previously-saved provider looks like on
            // page load. Parsed as HTML (the login page, Connected Accounts) the browser's own
            // SVG foreign-content fix-up silently restores it; parsed as standalone XML (this
            // preview's <img> data URL) it would not be, and the icon would lose its viewBox.
            const sanitizedSvg = '<svg xmlns="http://www.w3.org/2000/svg" viewbox="0 0 48 48"><path fill="#4285F4" d="M1 1"/></svg>';
            mount([{ id: 'g2', preset: 'google', label: 'google 2', icon: sanitizedSvg, enabled: true, order: 10 }]);

            const decoded = decodeURIComponent(container.querySelector('.plg-oauth-icon-preview').src
                .replace(/^data:image\/svg\+xml;charset=utf-8,/, ''));
            expect(decoded).toContain('viewBox="0 0 48 48"');
            expect(decoded).not.toMatch(/\bviewbox=/);
        });

        test('leaves the editable field showing the exact stored value, case restoration is preview-only', () => {
            const sanitizedSvg = '<svg xmlns="http://www.w3.org/2000/svg" viewbox="0 0 48 48"><path fill="#4285F4" d="M1 1"/></svg>';
            mount([{ id: 'g2', preset: 'google', icon: sanitizedSvg, enabled: true, order: 10 }]);
            q('.plg-oauth-edit-btn').click();

            expect(q('.plg-f-icon').value).toBe(sanitizedSvg);
        });

        test('updates the preview live as the icon is typed', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'corp');
            type('.plg-f-icon', '🏢');

            expect(container.querySelector('.plg-oauth-icon-preview').textContent).toBe('🏢');
        });

        test('agrees with the server that a missing enabled flag means off', () => {
            mount([{ id: 'legacy', preset: 'google', order: 10 }]);

            expect(tableText()).toContain('—');
            q('.plg-oauth-edit-btn').click();
            expect(q('.plg-f-enabled').checked).toBe(false);
        });

        test('clears a previously stored label back to inherited', () => {
            mount([{ id: 'google-corp', preset: 'google', label: 'Corp SSO', enabled: true, order: 10 }]);
            q('.plg-oauth-edit-btn').click();
            type('.plg-f-label', '   ');

            expect(reported[0]).not.toHaveProperty('label');
        });
    });

    describe('attribute-safe escaping', () => {
        test('an inline SVG icon round-trips through the form intact', () => {
            const svg = '<svg viewBox="0 0 24 24"><path d="M1 1"/></svg>';
            mount([{ id: 'corp', preset: 'oidc', icon: svg, enabled: true, order: 10 }]);
            q('.plg-oauth-edit-btn').click();

            expect(q('.plg-f-icon').value).toBe(svg);
        });

        test('a label containing a double quote cannot break out of value="..."', () => {
            const payload = 'x" onfocus="window.pwned=1';
            mount([{ id: 'corp', preset: 'oidc', label: payload, enabled: true, order: 10 }]);
            q('.plg-oauth-edit-btn').click();

            expect(q('.plg-f-label').value).toBe(payload);
            expect(q('.plg-f-label').hasAttribute('onfocus')).toBe(false);
        });
    });

    describe('add and delete are local array operations', () => {
        test('flags a draft row as needing an id, since a blank id fails the page save', () => {
            q('.plg-oauth-add-btn').click();

            expect(tableText()).toContain('(ID required)');
            expect(container.querySelector('.jp-text-danger').textContent).toBe('(ID required)');
            type('.plg-f-label', 'Anything');
            expect(q('.plg-oauth-form-error').textContent).toMatch(/Provider ID is required/);
        });

        test('rejects a duplicate id against the rows already in the table', () => {
            mount([{ id: 'google-corp', preset: 'google', enabled: true, order: 10 }]);
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'google-corp');

            expect(q('.plg-oauth-form-error').textContent).toMatch(/already used by another row/);
        });

        test('deletes a never-saved row without a confirm dialog', async () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'draft');
            all('.plg-oauth-delete-btn')[0].click();
            await Promise.resolve();

            expect(window.jPulse.UI.confirmDialog).not.toHaveBeenCalled();
            expect(reported).toEqual([]);
        });

        test('confirms before dropping a previously saved provider, and removes only that row', async () => {
            mount([
                { id: 'first', preset: 'google', enabled: true, order: 10 },
                { id: 'second', preset: 'oidc', enabled: true, order: 20 }
            ]);
            all('.plg-oauth-delete-btn')[0].click();
            await new Promise(resolve => setTimeout(resolve, 0));

            expect(window.jPulse.UI.confirmDialog).toHaveBeenCalled();
            expect(reported.map(p => p.id)).toEqual(['second']);
        });

        test('labels the panel-closing button so it cannot read as a commit action', () => {
            q('.plg-oauth-add-btn').click();
            expect(q('.plg-oauth-done-btn').textContent).toBe('Close Editor');

            q('.plg-oauth-done-btn').click();
            expect(q('.plg-f-id')).toBeNull(); // only collapses the panel
            expect(reported).toHaveLength(1); // the draft row stays in the pending value
        });

        test('preserves order 0 rather than defaulting it to 100', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-order', '0');

            expect(reported[0].order).toBe(0);
        });
    });

    describe('test connection', () => {
        test('is disabled for a row that only exists locally', () => {
            q('.plg-oauth-add-btn').click();
            type('.plg-f-id', 'google-corp');

            const testBtn = q('.plg-oauth-test-btn');
            expect(testBtn.disabled).toBe(true);
            expect(testBtn.title).toMatch(/Save Changes first/);
        });

        test('calls the admin endpoint for a saved provider', async () => {
            mount([{ id: 'google-corp', preset: 'google', enabled: true, order: 10 }]);
            q('.plg-oauth-test-btn').click();
            await new Promise(resolve => setTimeout(resolve, 0));

            expect(window.jPulse.api.post)
                .toHaveBeenCalledWith('/api/1/auth-oauth/admin/providers/google-corp/test');
            expect(window.jPulse.UI.toast.show)
                .toHaveBeenCalledWith(expect.stringContaining('Connection OK'), 'success');
        });
    });

    describe('JIT role override (W-147)', () => {
        test('per-provider role selector loads this site\'s actual roles, not a hardcoded list', async () => {
            // The admin/assignable-roles endpoint already excludes admin-equivalent roles
            // server-side - this fixture reflects that response shape, not the raw role list.
            mount([], { roles: ['user', 'editor'] });
            await new Promise(resolve => setTimeout(resolve, 0));
            q('.plg-oauth-add-btn').click();

            expect(all('.plg-f-jitRoles option').map(o => o.value)).toEqual(['user', 'editor']);
        });

        test('falls back to a plain "user" option if the roles fetch fails', async () => {
            mount([], { rolesFetchFails: true });
            await new Promise(resolve => setTimeout(resolve, 0));
            q('.plg-oauth-add-btn').click();

            expect(all('.plg-f-jitRoles option').map(o => o.value)).toEqual(['user']);
        });

        test('selecting nothing reports jitRoles as null (inherit the global default)', async () => {
            mount([{ id: 'okta', preset: 'oidc', enabled: true, order: 10, jitRoles: ['editor'] }],
                { roles: ['user', 'editor'] });
            await new Promise(resolve => setTimeout(resolve, 0));
            q('.plg-oauth-edit-btn').click();

            const select = q('.plg-f-jitRoles');
            expect(Array.from(select.selectedOptions).map(o => o.value)).toEqual(['editor']);

            Array.from(select.options).forEach(o => { o.selected = false; });
            select.dispatchEvent(new window.Event('change', { bubbles: true }));

            expect(reported[0].jitRoles).toBeNull();
        });

        test('selecting roles reports the exact site-defined roles chosen', async () => {
            mount([{ id: 'okta', preset: 'oidc', enabled: true, order: 10 }],
                { roles: ['user', 'editor', 'gofer'] });
            await new Promise(resolve => setTimeout(resolve, 0));
            q('.plg-oauth-edit-btn').click();

            const select = q('.plg-f-jitRoles');
            Array.from(select.options).forEach(o => { o.selected = (o.value === 'user' || o.value === 'editor'); });
            select.dispatchEvent(new window.Event('change', { bubbles: true }));

            expect(reported[0].jitRoles).toEqual(['user', 'editor']);
        });

        test('uses the same jpSelect dropdown widget as the rest of the config page, not a plain multiselect', () => {
            mount([{ id: 'okta', preset: 'oidc', enabled: true, order: 10 }]);
            q('.plg-oauth-edit-btn').click();

            expect(window.jPulse.UI.input.jpSelect.init).toHaveBeenCalledWith(q('.plg-f-jitRoles'));
            expect(q('.plg-f-jitRoles').closest('[data-jpselect-wrapper]')).not.toBeNull();
        });

        test('tears down the previous dropdown portal instead of leaking one into <body> per form open', () => {
            mount([
                { id: 'okta', preset: 'oidc', enabled: true, order: 10 },
                { id: 'auth0', preset: 'oidc', enabled: true, order: 20 }
            ]);

            all('.plg-oauth-edit-btn')[0].click();
            all('.plg-oauth-edit-btn')[1].click(); // switch rows without closing first
            q('.plg-oauth-done-btn').click(); // close - no form left open at all

            expect(window.document.body.querySelectorAll('.jp-jpselect-dropdown-stub')).toHaveLength(0);
        });
    });

    describe('read-only mode', () => {
        test('renders the table but no editing affordances when disabled', () => {
            mount([{ id: 'google-corp', preset: 'google', enabled: true, order: 10 }], { disabled: true });

            expect(tableText()).toContain('google-corp');
            expect(q('.plg-oauth-add-btn')).toBeNull();
            expect(q('.plg-oauth-edit-btn')).toBeNull();
            expect(q('.plg-oauth-delete-btn')).toBeNull();
        });
    });
});

// EOF plugins/auth-oauth/webapp/tests/unit/view/provider-renderer.test.js
