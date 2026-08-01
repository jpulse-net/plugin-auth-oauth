/*
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / View / jPulse Common JavaScript
 * @tagline         Custom renderer for the "Identity Providers" config field
 * @description     Appended to the framework's jpulse-common.js (append mode). Implements
 *                    window.jPulse.plugins.authOauth.renderProviders(ctx), the sole entry point
 *                    plugin.json's `{ type: "custom", renderer: "authOauth.renderProviders" }`
 *                    field resolves to (see webapp/controller/plugin-config.shtml's dispatcher).
 *                    Renders a table of OAuth/OIDC provider configs. Every field in the add/edit
 *                    form writes straight into the in-memory `providers` array on every keystroke/
 *                    change (see syncFormToEntry()) and reports it via ctx.onChange() - there is no
 *                    separate commit action (no per-row Save/Apply, nothing to Cancel). "+ Add
 *                    Provider" and Delete are local array operations too. The plugin config page's
 *                    single Save Changes button is the only thing that ever talks to the server for
 *                    persistence; its onPluginConfigBeforeSave hook (controller/oauthAuth.js) is
 *                    what actually validates, sanitizes, and encrypts a submitted clientSecret right
 *                    before that save is written. Test Connection is the one exception - it's not a
 *                    field edit, and needs a real, already-encrypted secret on the server to test
 *                    against, so it stays a dedicated admin-endpoint call and is disabled for a
 *                    provider that only exists locally (added this session, not yet saved).
 * @file            plugins/auth-oauth/webapp/view/jpulse-common.js
 * @version         1.0.0
 * @release         2026-07-31
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

if (!window.jPulse) {
    window.jPulse = {};
}
if (!window.jPulse.plugins) {
    window.jPulse.plugins = {};
}

/** The well-known 4-color Google "G" mark. No width/height/x/y - every place this renders (login
 *  button, table preview, Connected Accounts) sizes it via its own CSS instead, so there's one
 *  shape with no baked-in size to fight with. Must match the `google` preset's `icon` in
 *  utils/providerRegistry.js (the server-side source of truth actually used for login buttons) -
 *  duplicated here only because this is a plain browser script with no import mechanism to
 *  share it. */
const JPULSE_AUTH_OAUTH_GOOGLE_LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">' +
    '<path fill="#FFC107" d="M43.611,20.083H42V20H24v8h11.303c-1.649,4.657-6.08,8-11.303,8c-6.627,0-12-5.373-12-12c0-6.627,5.373-12,12-12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C12.955,4,4,12.955,4,24c0,11.045,8.955,20,20,20c11.045,0,20-8.955,20-20C44,22.659,43.862,21.35,43.611,20.083z"/>' +
    '<path fill="#FF3D00" d="M6.306,14.691l6.571,4.819C14.655,15.108,18.961,12,24,12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C16.318,4,9.656,8.337,6.306,14.691z"/>' +
    '<path fill="#4CAF50" d="M24,44c5.166,0,9.86-1.977,13.409-5.192l-6.19-5.238C29.211,35.091,26.715,36,24,36c-5.202,0-9.619-3.317-11.283-7.946l-6.522,5.025C9.505,39.556,16.227,44,24,44z"/>' +
    '<path fill="#1976D2" d="M43.611,20.083H42V20H24v8h11.303c-0.792,2.237-2.231,4.166-4.087,5.571c0.001-0.001,0.002-0.001,0.003-0.002l6.19,5.238C36.971,39.205,44,34,44,24C44,22.659,43.862,21.35,43.611,20.083z"/>' +
    '</svg>';

/** The classic Microsoft four-square mark. Must match the `microsoft` preset's `icon` in
 *  utils/providerRegistry.js - duplicated here for the same reason as the Google logo above. */
const JPULSE_AUTH_OAUTH_MICROSOFT_LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">' +
    '<path fill="#ff5722" d="M6 6H22V22H6z"/>' +
    '<path fill="#4caf50" d="M26 6H42V22H26z"/>' +
    '<path fill="#ffc107" d="M26 26H42V42H26z"/>' +
    '<path fill="#03a9f4" d="M6 26H22V42H6z"/>' +
    '</svg>';

window.jPulse.plugins.authOauth = {

    /**
     * This site's roles that a JIT-created user could actually end up with (W-147 roles minus
     * this site's admin-equivalent roles - the admin endpoint applies that filter server-side, via
     * the same `ConfigModel.getEffectiveAdminRoles()` check `sanitizeJitRoles()` enforces at
     * JIT-creation time), for the two JIT role selectors below. Memoized per script load - both
     * the global "JIT: Default Roles" multiselect (via the registered `loadOptions` handler) and
     * every open per-provider "JIT: Override Roles" form pull from the same fetch, and the role
     * list won't change mid-session. Falls back to a plain `user` option on any error, matching
     * the plugin.json field's own static fallback.
     * @returns {Promise<Array<{value: string, label: string}>>}
     */
    _fetchSiteRoles: function() {
        if (!this._siteRolesPromise) {
            this._siteRolesPromise = jPulse.api.get('/api/1/auth-oauth/admin/assignable-roles')
                .then((response) => {
                    const roles = (response && response.success && response.data && Array.isArray(response.data.roles) && response.data.roles.length) ?
                        response.data.roles : ['user'];
                    return roles.map((role) => ({ value: role, label: role }));
                })
                .catch(() => [{ value: 'user', label: 'user' }]);
        }
        return this._siteRolesPromise;
    },

    /**
     * Preset id -> UI defaults, mirroring utils/providerRegistry.js. `label`/`icon`/`buttonColor`
     * are the same values the server falls back to when the stored entry leaves them blank, so the
     * form can show them as placeholders - "blank means inherit" stays visible instead of implied.
     */
    _PRESETS: {
        google: { label: 'Google', icon: JPULSE_AUTH_OAUTH_GOOGLE_LOGO_SVG, buttonColor: '#4285F4', needsDiscoveryUrl: false, needsManualEndpoints: false },
        microsoft: {
            label: 'Microsoft Entra ID', icon: JPULSE_AUTH_OAUTH_MICROSOFT_LOGO_SVG, buttonColor: '#03a9f4',
            needsDiscoveryUrl: true, needsManualEndpoints: false,
            // Tenant-specific, unlike Google's single global URL - a realistic example beats the
            // generic oidc placeholder below at telling the admin what shape to paste in here.
            discoveryUrlPlaceholder: 'https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration'
        },
        oidc: { label: 'OIDC Provider', icon: '🔐', buttonColor: '#7f8fa6', needsDiscoveryUrl: true, needsManualEndpoints: false },
        oauth2: { label: 'OAuth2 Provider', icon: '🔑', buttonColor: '#7f8fa6', needsDiscoveryUrl: false, needsManualEndpoints: true }
    },

    /** Mirrors PROVIDER_ID_PATTERN in controller/oauthAuth.js. */
    _ID_PATTERN: /^[a-zA-Z0-9_-]{1,64}$/,

    /**
     * W-194 custom renderer for plugin.json's "providers" field.
     * @param {Object} ctx - { container, value, onChange, schema, config, disabled }
     */
    renderProviders: function(ctx) {
        const ns = jPulse.plugins.authOauth;
        const escape = jPulse.string.escapeHtml;
        const container = ctx.container;
        const disabled = !!ctx.disabled;
        // Deep copy, not slice(): every edit below mutates an entry in place, and ctx.value is the
        // config page's own object - sharing entries would let a half-typed draft bleed into it.
        const providers = Array.isArray(ctx.value) ? JSON.parse(JSON.stringify(ctx.value)) : [];
        // Rows added via "+ Add Provider" this session - identified by object reference, not id
        // (a new row's id starts blank and is user-editable). Governs whether the ID field is
        // still editable and whether Test Connection is available (needs a real saved secret).
        const newEntries = new WeakSet();
        let editingIndex = null; // index into `providers` of the open form's row, or null

        // W-147: this site's roles, for the per-provider "JIT: Override Roles" multiselect below.
        // Starts with the plain fallback so the first render (before the fetch resolves) still
        // shows something sane; refreshed in place once the real list arrives, re-rendering the
        // form only if it's actually open (the table doesn't display roles at all).
        let siteRoles = [{ value: 'user', label: 'user' }];
        ns._fetchSiteRoles().then((roles) => {
            if (Array.isArray(roles) && roles.length) {
                siteRoles = roles;
            }
            if (editingIndex !== null) {
                renderForm();
            }
        });

        /**
         * Escape for interpolation into a double-quoted HTML attribute. jPulse.string.escapeHtml()
         * serializes a text node, which per the HTML spec leaves `"` untouched - correct for
         * element content, but in an attribute it lets the value break out of its own quotes (an
         * SVG icon like <svg viewBox="0 0 24 24"> does it by accident, a crafted label on purpose).
         */
        function attrEscape(value) {
            return String(value == null ? '' : value)
                .replace(/&/g, '&amp;')
                .replace(/"/g, '&quot;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
        }

        function presetDefOf(entry) {
            return ns._PRESETS[entry && entry.preset] || ns._PRESETS.google;
        }

        /** A raw SVG string would just show as unreadable markup in a text input's `placeholder`
         *  attribute - describe it instead. An emoji preset's icon reads fine as-is. */
        function iconPlaceholderOf(presetDef) {
            return presetDef.icon.includes('<') ? `(${presetDef.label} logo)` : presetDef.icon;
        }

        /**
         * A previously-saved icon has already been through the server's `sanitizeIcon()`, which
         * lowercases every attribute name it re-serializes (`CommonUtils.sanitizeHtml()`) -
         * including `viewBox`, which becomes `viewbox`. That's harmless when the markup is parsed
         * as HTML (the login page's `{{this.icon}}`, the Connected Accounts page's `innerHTML`):
         * the HTML parser's own SVG "foreign content" step silently restores the correct casing
         * for a fixed list of attributes, `viewbox` -> `viewBox` among them. It does *not* happen
         * here: iconPreviewHtml() below deliberately loads the icon through an `<img>` data URL
         * instead of inserting it as HTML (so a not-yet-saved, not-yet-sanitized draft can't
         * become live DOM in the admin's own page) - and SVG behind an `<img>` is parsed as a
         * standalone XML document, which is case-sensitive and has no such fix-up. Without it the
         * icon silently loses its viewBox and renders tiny and mis-positioned. `viewbox` is the
         * only mixed-case attribute in ICON_SVG_ALLOWED_ATTRIBUTES (oauthAuth.js) today; restoring
         * it here is idempotent on an icon that's still correctly cased (not yet saved).
         */
        function restoreSvgAttributeCase(svg) {
            return svg.replace(/\bviewbox=/gi, 'viewBox=');
        }

        /**
         * Small preview of an icon value for the table. An emoji renders as itself; anything that
         * looks like markup goes through an `<img>` data URL rather than into the DOM as HTML -
         * this renderer may hold either a not-yet-saved value (the server hasn't sanitized it yet)
         * or a previously-saved one (already sanitized, and re-cased per the above), and an SVG
         * loaded via `<img>` can neither run script nor fetch anything either way.
         */
        function iconPreviewHtml(icon) {
            if (!icon) {
                return '';
            }
            if (!icon.includes('<')) {
                return '<span class="plg-oauth-icon-preview">' + escape(icon) + '</span>';
            }
            let markup = restoreSvgAttributeCase(icon);
            // Inline SVG in an HTML document doesn't need xmlns, but SVG behind an <img> does -
            // add it when it's missing so a valid icon never previews as a broken image.
            if (!/<svg[^>]*\sxmlns\s*=/i.test(markup)) {
                markup = markup.replace(/<svg\b/i, '<svg xmlns="http://www.w3.org/2000/svg"');
            }
            const dataUrl = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(markup);
            return '<img class="plg-oauth-icon-preview" src="' + attrEscape(dataUrl) + '" alt="">';
        }

        function redirectUri(id) {
            return `${window.location.origin}/api/1/auth-oauth/callback/${encodeURIComponent(id || '')}`;
        }

        function toList(text) {
            return String(text || '').split(',').map(s => s.trim()).filter(Boolean);
        }

        /** <option>s for the "JIT: Override Roles" multiselect, from the current `siteRoles`. */
        function roleOptionsHtml(selectedRoles) {
            const selected = new Set(Array.isArray(selectedRoles) ? selectedRoles : []);
            return siteRoles.map((role) =>
                `<option value="${attrEscape(role.value)}"${selected.has(role.value) ? ' selected' : ''}>${escape(role.label)}</option>`
            ).join('');
        }

        // jPulse.UI.input.jpSelect.init() appends its dropdown to document.body (portal, not a
        // descendant of `container`), so replacing container/formEl innerHTML - which this
        // renderer does on nearly every open/close/switch - never removes it on its own. Track
        // the one dropdown this renderer ever owns and tear it down ourselves before every
        // re-render that would discard its native <select>, or it leaks one abandoned dropdown
        // <div> into <body> per edit-form open over the life of the page.
        let jitRolesDropdownEl = null;
        function destroyJitRolesWidget() {
            if (jitRolesDropdownEl && jitRolesDropdownEl.parentNode) {
                jitRolesDropdownEl.parentNode.removeChild(jitRolesDropdownEl);
            }
            jitRolesDropdownEl = null;
        }

        /** Enhance the "JIT: Override Roles" <select multiple> with the same jpSelect dropdown
         *  widget the framework's own schema-form fields use (e.g. "JIT: Default Roles" on the
         *  General tab) - a plain multi-select listbox is the same control, just visually
         *  inconsistent with the rest of the config page. */
        function initJitRolesWidget(formEl) {
            const select = formEl.querySelector('.plg-f-jitRoles');
            if (!select) {
                return;
            }
            jPulse.UI.input.jpSelect.init(select);
            const wrap = select.closest('[data-jpselect-wrapper]');
            jitRolesDropdownEl = wrap ? wrap._jpSelectDropdown : null;
        }

        render();

        /** Full re-render: table + (optional) add/edit form. Only called at row-count-changing or
         *  form-open/close checkpoints; keystrokes go through refreshTable() so focus survives. */
        function render() {
            destroyJitRolesWidget();
            container.innerHTML =
                '<div class="jp-table-container plg-oauth-table-container">' +
                '<table class="jp-table plg-oauth-table">' +
                '<thead><tr>' +
                '<th>ID</th><th>Preset</th><th>Icon &amp; Label</th><th>Order</th><th>Enabled</th><th></th>' +
                '</tr></thead>' +
                '<tbody>' + tableRowsHtml() + '</tbody>' +
                '</table></div>' +
                (disabled ? '' : '<button type="button" class="jp-btn jp-btn-sm jp-btn-secondary plg-oauth-add-btn">+ Add Provider</button>') +
                '<div class="plg-oauth-form-container"></div>';

            if (!disabled) {
                container.querySelector('.plg-oauth-add-btn').addEventListener('click', onAdd);
                wireRowButtons();
            }
            if (editingIndex !== null) {
                renderForm();
            }
        }

        /** Repaint only the table body, so its summary columns track the open form's live edits
         *  without touching the form subtree - re-rendering that would drop focus mid-keystroke. */
        function refreshTable() {
            const tbody = container.querySelector('.plg-oauth-table tbody');
            if (!tbody) {
                return;
            }
            tbody.innerHTML = tableRowsHtml();
            if (!disabled) {
                wireRowButtons();
            }
        }

        /** (Re-)binds the per-row buttons. Safe to call after any tbody repaint - the previous
         *  buttons (and their listeners) are gone with the replaced markup. */
        function wireRowButtons() {
            container.querySelectorAll('.plg-oauth-edit-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    editingIndex = Number(btn.dataset.index);
                    renderForm();
                });
            });
            container.querySelectorAll('.plg-oauth-delete-btn').forEach(btn => {
                btn.addEventListener('click', () => onDelete(Number(btn.dataset.index)));
            });
            container.querySelectorAll('.plg-oauth-test-btn').forEach(btn => {
                if (!btn.disabled) {
                    btn.addEventListener('click', () => onTest(Number(btn.dataset.index), btn));
                }
            });
        }

        function tableRowsHtml() {
            if (providers.length === 0) {
                return '<tr><td colspan="6" class="jp-text-small jp-text-muted plg-oauth-empty">No providers configured yet.</td></tr>';
            }
            return providers.map(rowHtml).join('');
        }

        /** One table row. Blank label/icon are shown muted with the preset's value, matching what
         *  the login page will actually render - "inherited", not "missing". */
        function rowHtml(entry, index) {
            const knownPreset = ns._PRESETS[entry.preset];
            const presetDef = presetDefOf(entry);
            const isNew = newEntries.has(entry);
            const idCell = entry.id ? escape(entry.id) :
                '<span class="jp-text-danger">(ID required)</span>';
            // Show an unrecognized preset key verbatim rather than presetDefOf()'s display fallback.
            const presetCell = escape(knownPreset ? knownPreset.label : (entry.preset || ''));
            const labelCell = '<span class="plg-oauth-label-cell">' +
                iconPreviewHtml(entry.icon || presetDef.icon) +
                (entry.label ? escape(entry.label) :
                    '<span class="jp-text-muted">' + escape(presetDef.label) + '</span>') +
                '</span>';
            const testTitle = isNew ?
                'Click Save Changes first - Test uses the provider config stored on the server' :
                'Tests the configuration last saved on the server, not unsaved edits';
            return '<tr>' +
                '<td>' + idCell + '</td>' +
                '<td>' + presetCell + '</td>' +
                '<td>' + labelCell + '</td>' +
                '<td>' + escape(String(entry.order != null ? entry.order : 100)) + '</td>' +
                '<td>' + (entry.enabled ? '✅' : '—') + '</td>' +
                '<td class="plg-oauth-row-actions">' +
                (disabled ? '' :
                    '<button type="button" class="jp-btn jp-btn-sm jp-btn-secondary plg-oauth-test-btn" data-index="' + index + '"' +
                        (isNew ? ' disabled' : '') + ' title="' + attrEscape(testTitle) + '">Test</button> ' +
                    '<button type="button" class="jp-btn jp-btn-sm jp-btn-secondary plg-oauth-edit-btn" data-index="' + index + '">Edit</button> ' +
                    '<button type="button" class="jp-btn jp-btn-sm jp-btn-danger plg-oauth-delete-btn" data-index="' + index + '">Delete</button>') +
                '</td>' +
                '</tr>';
        }

        /** Append a draft row and open its form. Local only, like every other edit here - the row
         *  is flagged "(ID required)" until it has an id, since a blank id fails the page save. */
        function onAdd() {
            const draft = { id: '', preset: 'google', enabled: true, order: 100 };
            newEntries.add(draft);
            providers.push(draft);
            editingIndex = providers.length - 1;
            ctx.onChange(providers);
            render();
        }

        /** Render the add/edit form below the table for `providers[editingIndex]`. */
        function renderForm() {
            destroyJitRolesWidget();
            const entry = providers[editingIndex];
            if (!entry) {
                editingIndex = null;
                return;
            }
            const isNew = newEntries.has(entry);
            const presetDef = presetDefOf(entry);

            const presetOptions = Object.keys(ns._PRESETS).map(key =>
                `<option value="${key}"${key === (entry.preset || 'google') ? ' selected' : ''}>${escape(ns._PRESETS[key].label)}</option>`).join('');
            const linkingOptions = [
                ['', 'Inherit global default'],
                ['sub-only', 'Sub only'],
                ['link-by-email', 'Link by verified email'],
                ['jit-create', 'JIT create']
            ].map(([value, label]) =>
                `<option value="${value}"${(entry.linkingStrategy || '') === value ? ' selected' : ''}>${escape(label)}</option>`).join('');
            const statusOptions = [
                ['', 'Inherit global default'],
                ['active', 'Active'],
                ['pending', 'Pending approval']
            ].map(([value, label]) =>
                `<option value="${value}"${(entry.jitStatus || '') === value ? ' selected' : ''}>${escape(label)}</option>`).join('');

            const formEl = container.querySelector('.plg-oauth-form-container');
            formEl.innerHTML =
                '<div class="jp-form-group plg-oauth-form">' +
                '<h4>' + (isNew ? 'Add Provider' : 'Edit Provider: ' + escape(entry.id)) + '</h4>' +

                fieldRow('ID', `<input type="text" class="jp-form-input plg-f-id" value="${attrEscape(entry.id || '')}"` +
                    (isNew ? ' placeholder="e.g. google-corp, okta-prod"' : ' disabled') + '>',
                    'Unique key - becomes /api/1/auth-oauth/init/&lt;id&gt;. Cannot be changed after creation.') +

                fieldRow('Preset', `<select class="jp-form-input plg-f-preset">${presetOptions}</select>`, '') +

                fieldRow('Label', `<input type="text" class="jp-form-input plg-f-label" value="${attrEscape(entry.label || '')}" placeholder="${attrEscape(presetDef.label)}">`,
                    'Shown on the login button and on the user\'s Connected Accounts page. Leave blank to use the preset default.') +
                fieldRow('Icon', `<input type="text" class="jp-form-input plg-f-icon" value="${attrEscape(entry.icon || '')}" placeholder="${attrEscape(iconPlaceholderOf(presetDef))}">`,
                    'Emoji or a small inline SVG (e.g. &lt;svg&gt;...&lt;/svg&gt;) - not an image URL. Shown next to the label; preview in the table above. Markup is sanitized server-side. Leave blank to use the preset default.') +
                fieldRow('Button Color', `<input type="color" class="plg-f-buttonColor" value="${attrEscape(entry.buttonColor || presetDef.buttonColor)}">`,
                    'Border color of this provider\'s button on the login page.') +
                fieldRow('Order', `<input type="number" class="jp-form-input plg-f-order" value="${attrEscape(entry.order != null ? entry.order : 100)}">`, 'Button order on the login page') +
                // Checked only when truthy, matching both the table column and the server's own
                // `.filter(p => p.enabled)` - a legacy entry with no `enabled` key really is off.
                fieldRow('Enabled', `<input type="checkbox" class="plg-f-enabled"${entry.enabled ? ' checked' : ''}>`, '') +

                fieldRow('Client ID', `<input type="text" class="jp-form-input plg-f-clientId" value="${attrEscape(entry.clientId || '')}">`, '') +
                fieldRow('Client Secret', `<input type="password" class="jp-form-input plg-f-clientSecret" placeholder="${(entry.clientSecretRef || entry.clientSecret) ? 'Leave blank to keep existing secret' : ''}" autocomplete="new-password">`, '') +
                fieldRow('Scopes', `<input type="text" class="jp-form-input plg-f-scopes" value="${attrEscape((entry.scopes || []).join(', '))}" placeholder="openid, email, profile">`, 'Comma-separated. Leave blank to use the preset default.') +

                (presetDef.needsDiscoveryUrl ?
                    fieldRow('Discovery URL', `<input type="text" class="jp-form-input plg-f-discoveryUrl" value="${attrEscape(entry.discoveryUrl || '')}" placeholder="${attrEscape(presetDef.discoveryUrlPlaceholder || 'https://.../.well-known/openid-configuration')}">`, '') : '') +

                (presetDef.needsManualEndpoints ?
                    fieldRow('Authorize URL', `<input type="text" class="jp-form-input plg-f-authorizeUrl" value="${attrEscape(entry.authorizeUrl || '')}">`, '') +
                    fieldRow('Token URL', `<input type="text" class="jp-form-input plg-f-tokenUrl" value="${attrEscape(entry.tokenUrl || '')}">`, '') +
                    fieldRow('Userinfo URL', `<input type="text" class="jp-form-input plg-f-userinfoUrl" value="${attrEscape(entry.userinfoUrl || '')}">`, '') +
                    fieldRow('Userinfo Mapping', `<textarea class="jp-form-textarea plg-f-userinfoMapping" rows="2" placeholder='{"sub":"id","email":"primary_email"}'>${escape(entry.userinfoMapping ? JSON.stringify(entry.userinfoMapping) : '')}</textarea>`, 'JSON object mapping jPulse claim names to this provider\'s userinfo field names.') : '') +

                fieldRow('Linking Strategy', `<select class="jp-form-input plg-f-linkingStrategy">${linkingOptions}</select>`, 'Overrides the global default for this provider only') +
                fieldRow('Allowed Domains', `<input type="text" class="jp-form-input plg-f-allowedDomains" value="${attrEscape((entry.allowedDomains || []).join(', '))}" placeholder="corp.example.com">`, 'Comma-separated. Leave blank to allow any domain.') +
                fieldRow('JIT: Override Roles', `<select multiple class="jp-form-input plg-f-jitRoles" size="3">${roleOptionsHtml(entry.jitRoles)}</select>`,
                    'Roles assigned to users JIT-created via this provider, overriding the global "JIT: Default Roles". Select nothing to inherit the global default. This site\'s admin roles are never shown here and can never be auto-provisioned this way.') +
                fieldRow('JIT: Status', `<select class="jp-form-input plg-f-jitStatus">${statusOptions}</select>`, '') +

                fieldRow('Redirect URI', `<input type="text" class="jp-form-input plg-f-redirectUri" value="${attrEscape(redirectUri(entry.id))}" readonly> ` +
                    '<button type="button" class="jp-btn jp-btn-sm jp-btn-secondary plg-oauth-copy-btn">Copy</button>',
                    'Paste this into the identity provider\'s console as the allowed redirect/callback URI.') +

                // "Close Editor", not "Done": this only collapses the panel. Every edit above is
                // already applied to the table; nothing here commits or discards anything.
                '<div class="plg-oauth-form-actions">' +
                '<button type="button" class="jp-btn jp-btn-secondary plg-oauth-done-btn">Close Editor</button>' +
                '<span class="plg-oauth-form-error jp-text-danger"></span>' +
                '</div>' +
                '<div class="jp-text-small jp-text-muted plg-oauth-form-hint">' +
                'Changes above update the table immediately. Click the page\'s own Save Changes button to persist them.' +
                '</div>' +
                '</div>';

            // Keep the redirect URI preview live as the admin types a new id.
            if (isNew) {
                formEl.querySelector('.plg-f-id').addEventListener('input', (event) => {
                    formEl.querySelector('.plg-f-redirectUri').value = redirectUri(event.target.value.trim());
                });
            }
            formEl.querySelector('.plg-oauth-copy-btn').addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(formEl.querySelector('.plg-f-redirectUri').value);
                    jPulse.UI.toast.show('Redirect URI copied to clipboard', 'success');
                } catch (error) {
                    void error; // clipboard API can be unavailable (e.g. non-HTTPS) - fail silently
                }
            });
            formEl.querySelector('.plg-oauth-done-btn').addEventListener('click', () => {
                editingIndex = null;
                render();
            });
            formEl.querySelector('.plg-f-preset').addEventListener('change', () => {
                const previousDefaultColor = presetDefOf(entry).buttonColor;
                syncFormToEntry(entry); // picks up the new preset, plus anything already typed
                // A color still sitting on the previous preset's default was never deliberately
                // picked - let it follow the new preset instead of freezing the old brand color.
                if (String(entry.buttonColor).toLowerCase() === String(previousDefaultColor).toLowerCase()) {
                    delete entry.buttonColor;
                    ctx.onChange(providers); // onChange snapshots, so re-report after the delete
                }
                renderForm(); // the preset decides which endpoint fields are shown
            });

            // Every other field writes straight into `entry` (already live in `providers`) on
            // every input/change - there is no separate commit step (see file header).
            formEl.querySelectorAll('input, select, textarea').forEach(el => {
                if (el.classList.contains('plg-f-preset') || el.classList.contains('plg-f-redirectUri')) {
                    return; // preset handled above; redirectUri is read-only/derived
                }
                const eventName = (el.tagName === 'SELECT' || el.type === 'checkbox' || el.type === 'color') ? 'change' : 'input';
                el.addEventListener(eventName, () => syncFormToEntry(entry));
            });

            // jpSelect only relocates/wraps the native <select> above - it stays the same node,
            // so the listener just attached to it keeps firing on every selection change.
            initJitRolesWidget(formEl);

            function fieldRow(label, inputHtml, help) {
                return '<div class="jp-form-group plg-oauth-field-row">' +
                    '<label class="jp-form-label">' + escape(label) + '</label>' +
                    inputHtml +
                    (help ? '<div class="jp-text-small jp-text-muted">' + help + '</div>' : '') +
                    '</div>';
            }
        }

        /**
         * Reads every field currently in the open form and writes the values straight into
         * `entry` (mutating the object already referenced from `providers`), then reports the
         * array via ctx.onChange() - this is the only place data moves from the form into the
         * pending-to-be-saved state, called on every keystroke/change, not from a Save button.
         * Validation issues are shown inline but never block typing or syncing; the real
         * enforcement is server-side (onPluginConfigBeforeSave) when the page is actually saved.
         */
        function syncFormToEntry(entry) {
            const formEl = container.querySelector('.plg-oauth-form-container');
            const errorEl = formEl.querySelector('.plg-oauth-form-error');
            errorEl.textContent = '';

            if (newEntries.has(entry)) {
                const typedId = formEl.querySelector('.plg-f-id').value.trim();
                entry.id = typedId;
                if (!typedId) {
                    errorEl.textContent = 'Provider ID is required before this page can be saved';
                } else if (!ns._ID_PATTERN.test(typedId)) {
                    errorEl.textContent = 'Provider ID may only contain letters, digits, "-" and "_"';
                } else if (providers.some(other => other !== entry && other.id === typedId)) {
                    errorEl.textContent = `Provider id '${typedId}' is already used by another row`;
                }
            }

            entry.preset = formEl.querySelector('.plg-f-preset').value;
            const presetDef = presetDefOf(entry);

            // Blank label/icon are stored as "absent" rather than "" so the server and the login
            // page fall back to the preset's own label/icon - "" would override them with nothing.
            const label = formEl.querySelector('.plg-f-label').value.trim();
            if (label) {
                entry.label = label;
                if (/[<>]/.test(label) && !errorEl.textContent) {
                    errorEl.textContent = 'Label may not contain "<" or ">"';
                }
            } else {
                delete entry.label;
            }
            const icon = formEl.querySelector('.plg-f-icon').value.trim();
            if (icon) {
                entry.icon = icon;
            } else {
                delete entry.icon;
            }

            const order = parseInt(formEl.querySelector('.plg-f-order').value, 10);
            entry.buttonColor = formEl.querySelector('.plg-f-buttonColor').value;
            entry.order = Number.isFinite(order) ? order : 100; // 0 is a valid order, don't ||-default it
            entry.enabled = formEl.querySelector('.plg-f-enabled').checked;
            entry.clientId = formEl.querySelector('.plg-f-clientId').value.trim();
            entry.scopes = toList(formEl.querySelector('.plg-f-scopes').value);
            entry.linkingStrategy = formEl.querySelector('.plg-f-linkingStrategy').value || null;
            entry.allowedDomains = toList(formEl.querySelector('.plg-f-allowedDomains').value);
            const selectedJitRoles = Array.from(formEl.querySelector('.plg-f-jitRoles').selectedOptions).map(o => o.value);
            entry.jitRoles = selectedJitRoles.length > 0 ? selectedJitRoles : null;
            entry.jitStatus = formEl.querySelector('.plg-f-jitStatus').value || null;

            // Endpoint fields are gated on the *new* preset, not just on the field being present:
            // during a preset change this runs against the outgoing preset's DOM, and a leftover
            // discoveryUrl/authorizeUrl would silently override the incoming preset's own defaults.
            const discoveryUrlEl = formEl.querySelector('.plg-f-discoveryUrl');
            if (presetDef.needsDiscoveryUrl && discoveryUrlEl) {
                entry.discoveryUrl = discoveryUrlEl.value.trim();
            } else {
                delete entry.discoveryUrl;
            }
            const authorizeUrlEl = formEl.querySelector('.plg-f-authorizeUrl');
            if (presetDef.needsManualEndpoints && authorizeUrlEl) {
                entry.authorizeUrl = authorizeUrlEl.value.trim();
                entry.tokenUrl = formEl.querySelector('.plg-f-tokenUrl').value.trim();
                entry.userinfoUrl = formEl.querySelector('.plg-f-userinfoUrl').value.trim();
                const mappingText = formEl.querySelector('.plg-f-userinfoMapping').value.trim();
                if (mappingText) {
                    try {
                        entry.userinfoMapping = JSON.parse(mappingText);
                    } catch (error) {
                        void error; // keep the last valid value; never block typing mid-object
                        if (!errorEl.textContent) {
                            errorEl.textContent = 'Userinfo Mapping is not valid JSON yet - the last valid value is kept';
                        }
                    }
                } else {
                    delete entry.userinfoMapping;
                }
            } else {
                delete entry.authorizeUrl;
                delete entry.tokenUrl;
                delete entry.userinfoUrl;
                delete entry.userinfoMapping;
            }

            const clientSecret = formEl.querySelector('.plg-f-clientSecret').value;
            if (clientSecret) {
                entry.clientSecret = clientSecret;
            } else {
                delete entry.clientSecret;
            }

            ctx.onChange(providers);
            refreshTable();
        }

        /**
         * Removes a row from the in-memory array - purely local, same as every other edit here.
         * A never-saved (this-session-only) row is removed immediately; a previously-saved
         * provider still gets a confirm dialog, since removing it has a real-world effect
         * (existing linked users) once the page's own Save Changes button is clicked.
         */
        async function onDelete(index) {
            const entry = providers[index];
            if (!entry) {
                return;
            }
            if (!newEntries.has(entry)) {
                const result = await jPulse.UI.confirmDialog({
                    title: 'Delete Provider',
                    message: `Delete provider "${entry.id}"? Users who signed in via this provider will no longer be able to use it. ` +
                        'This takes effect once you click the page\'s own Save Changes button.',
                    buttons: ['Cancel', 'Delete']
                });
                if (!result.confirmed) {
                    return;
                }
            }

            // Re-resolve by identity: the dialog above is awaited, so `index` is only a starting hint.
            const position = providers.indexOf(entry);
            if (position < 0) {
                return;
            }
            providers.splice(position, 1);
            if (editingIndex === position) {
                editingIndex = null;
            } else if (editingIndex !== null && editingIndex > position) {
                editingIndex -= 1;
            }
            ctx.onChange(providers);
            render();
        }

        async function onTest(index, btn) {
            const entry = providers[index];
            if (!entry) {
                return;
            }
            const originalText = btn.textContent;
            btn.textContent = 'Testing...';
            btn.disabled = true;
            try {
                const response = await jPulse.api.post(`/api/1/auth-oauth/admin/providers/${encodeURIComponent(entry.id)}/test`);
                if (!response.success) {
                    jPulse.UI.toast.show(response.error || 'Connection test failed', 'error');
                } else {
                    jPulse.UI.toast.show(`Connection OK - issuer: ${response.data.issuer}`, 'success');
                }
            } catch (error) {
                void error;
                jPulse.UI.toast.show('Network error - please try again', 'error');
            } finally {
                btn.textContent = originalText;
                btn.disabled = false;
            }
        }
    }
};

/**
 * W-189/W-147 `loadOptions` handler for the "JIT: Default Roles" schema-form field in plugin.json
 * (`loadOptions: "authOauth.loadRoleOptions"`) - resolves this site's actually-configured roles
 * instead of the static single-option fallback declared there.
 */
jPulse.schemaForm.register('authOauth.loadRoleOptions', () => window.jPulse.plugins.authOauth._fetchSiteRoles());

// EOF plugins/auth-oauth/webapp/view/jpulse-common.js
