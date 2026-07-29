/*
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / View / jPulse Common JavaScript
 * @tagline         W-194 custom renderer for the "Identity Providers" config field
 * @description     Appended to the framework's jpulse-common.js (W-098 append mode). Implements
 *                    window.jPulse.plugins.authOauth.renderProviders(ctx), the sole entry point
 *                    plugin.json's `{ type: "custom", renderer: "authOauth.renderProviders" }`
 *                    field resolves to (see webapp/controller/plugin-config.shtml's dispatcher).
 *                    Renders a CRUD table of OAuth/OIDC provider configs; every write (create /
 *                    update / delete / test) goes straight to the plugin's dedicated
 *                    /api/1/auth-oauth/admin/providers* endpoints rather than the generic plugin
 *                    config save - those endpoints are what actually encrypt a submitted
 *                    clientSecret before it touches storage (see controller/oauthAuth.js). After
 *                    each successful call we also report the new array via ctx.onChange() so the
 *                    page's own Save button (for the General/Security tabs) has a consistent
 *                    value if clicked afterwards. See W-197 design doc, "UI Components" §3.
 * @file            plugins/auth-oauth/webapp/view/jpulse-common.js
 * @version         1.0.0
 * @release         2026-07-29
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

window.jPulse.plugins.authOauth = {

    /** Preset id -> { label, needsDiscoveryUrl, needsManualEndpoints } (mirrors providerRegistry.js). */
    _PRESETS: {
        google: { label: 'Google', needsDiscoveryUrl: false, needsManualEndpoints: false },
        oidc: { label: 'OIDC Provider', needsDiscoveryUrl: true, needsManualEndpoints: false },
        oauth2: { label: 'OAuth2 Provider', needsDiscoveryUrl: false, needsManualEndpoints: true }
    },

    /**
     * W-194 custom renderer for plugin.json's "providers" field.
     * @param {Object} ctx - { container, value, onChange, schema, config, disabled }
     */
    renderProviders: function(ctx) {
        const ns = jPulse.plugins.authOauth;
        const container = ctx.container;
        const disabled = !!ctx.disabled;
        let providers = Array.isArray(ctx.value) ? ctx.value.slice() : [];
        let editingId = null; // null = no form open; '__new__' = create form; else editing this id
        let formPresetOverride = null; // live preset selection while the add/edit form is open

        function providerById(id) {
            return providers.find(p => p.id === id) || null;
        }

        function redirectUri(id) {
            return `${window.location.origin}/api/1/auth-oauth/callback/${encodeURIComponent(id || '')}`;
        }

        function toList(text) {
            return String(text || '').split(',').map(s => s.trim()).filter(Boolean);
        }

        render();

        /** Full re-render: table + (optional) add/edit form. */
        function render() {
            const escape = jPulse.string.escapeHtml;
            const rows = providers.length > 0 ? providers.map(rowHtml).join('') :
                '<tr><td colspan="6" class="jp-text-small jp-text-muted plg-oauth-empty">No providers configured yet.</td></tr>';

            container.innerHTML =
                '<div class="jp-table-container plg-oauth-table-container">' +
                '<table class="jp-table plg-oauth-table">' +
                '<thead><tr>' +
                '<th>ID</th><th>Preset</th><th>Label</th><th>Order</th><th>Enabled</th><th></th>' +
                '</tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
                '</table></div>' +
                (disabled ? '' : '<button type="button" class="jp-btn jp-btn-sm jp-btn-secondary plg-oauth-add-btn">+ Add Provider</button>') +
                '<div class="plg-oauth-form-container"></div>';

            if (!disabled) {
                container.querySelector('.plg-oauth-add-btn').addEventListener('click', () => {
                    editingId = '__new__';
                    formPresetOverride = null;
                    renderForm();
                });
                container.querySelectorAll('.plg-oauth-edit-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        editingId = btn.dataset.id;
                        formPresetOverride = null;
                        renderForm();
                    });
                });
                container.querySelectorAll('.plg-oauth-delete-btn').forEach(btn => {
                    btn.addEventListener('click', () => onDelete(btn.dataset.id));
                });
                container.querySelectorAll('.plg-oauth-test-btn').forEach(btn => {
                    btn.addEventListener('click', () => onTest(btn.dataset.id, btn));
                });
            }

            if (editingId) {
                renderForm();
            }

            function rowHtml(p) {
                return '<tr>' +
                    '<td>' + escape(p.id) + '</td>' +
                    '<td>' + escape((ns._PRESETS[p.preset] || {}).label || p.preset) + '</td>' +
                    '<td>' + escape(p.label || '') + '</td>' +
                    '<td>' + escape(String(p.order != null ? p.order : 100)) + '</td>' +
                    '<td>' + (p.enabled ? '✅' : '—') + '</td>' +
                    '<td class="plg-oauth-row-actions">' +
                    (disabled ? '' :
                        '<button type="button" class="jp-btn jp-btn-sm jp-btn-secondary plg-oauth-test-btn" data-id="' + escape(p.id) + '">Test</button> ' +
                        '<button type="button" class="jp-btn jp-btn-sm jp-btn-secondary plg-oauth-edit-btn" data-id="' + escape(p.id) + '">Edit</button> ' +
                        '<button type="button" class="jp-btn jp-btn-sm jp-btn-danger plg-oauth-delete-btn" data-id="' + escape(p.id) + '">Delete</button>') +
                    '</td>' +
                    '</tr>';
            }
        }

        /** Render the add/edit form below the table for the current `editingId`. */
        function renderForm() {
            const escape = jPulse.string.escapeHtml;
            const isNew = editingId === '__new__';
            // Shallow-clone so previewing a preset change (which re-renders this form) never
            // mutates the live `providers` array until the admin actually clicks Save.
            const p = isNew ? {} : { ...(providerById(editingId) || {}) };
            const preset = formPresetOverride || p.preset || 'google';
            const presetDef = ns._PRESETS[preset] || ns._PRESETS.google;

            const presetOptions = Object.keys(ns._PRESETS).map(key =>
                `<option value="${key}"${key === preset ? ' selected' : ''}>${escape(ns._PRESETS[key].label)}</option>`).join('');
            const linkingOptions = [
                ['', 'Inherit global default'],
                ['sub-only', 'Sub only'],
                ['link-by-email', 'Link by verified email'],
                ['jit-create', 'JIT create']
            ].map(([value, label]) =>
                `<option value="${value}"${p.linkingStrategy === value ? ' selected' : ''}>${escape(label)}</option>`).join('');
            const statusOptions = [
                ['', 'Inherit global default'],
                ['active', 'Active'],
                ['pending', 'Pending approval']
            ].map(([value, label]) =>
                `<option value="${value}"${p.jitStatus === value ? ' selected' : ''}>${escape(label)}</option>`).join('');

            const formEl = container.querySelector('.plg-oauth-form-container');
            formEl.innerHTML =
                '<div class="jp-form-group plg-oauth-form">' +
                '<h4>' + (isNew ? 'Add Provider' : 'Edit Provider: ' + escape(editingId)) + '</h4>' +

                fieldRow('ID', `<input type="text" class="jp-form-input plg-f-id" value="${escape(p.id || '')}"` +
                    (isNew ? ' placeholder="e.g. google-corp, okta-prod"' : ' disabled') + '>',
                    'Unique key - becomes /api/1/auth-oauth/init/&lt;id&gt;. Cannot be changed after creation.') +

                fieldRow('Preset', `<select class="jp-form-input plg-f-preset">${presetOptions}</select>`, '') +

                fieldRow('Label', `<input type="text" class="jp-form-input plg-f-label" value="${escape(p.label || '')}" placeholder="Sign in with...">`, '') +
                fieldRow('Icon', `<input type="text" class="jp-form-input plg-f-icon" value="${escape(p.icon || '')}" placeholder="Emoji, e.g. 🔐">`,
                    'Emoji or a small inline SVG (e.g. &lt;svg&gt;...&lt;/svg&gt;) - not an image URL. Markup is sanitized server-side.') +
                fieldRow('Button Color', `<input type="color" class="plg-f-buttonColor" value="${escape(p.buttonColor || '#7f8fa6')}">`, '') +
                fieldRow('Order', `<input type="number" class="jp-form-input plg-f-order" value="${p.order != null ? p.order : 100}">`, 'Button order on the login page') +
                fieldRow('Enabled', `<input type="checkbox" class="plg-f-enabled"${p.enabled !== false ? ' checked' : ''}>`, '') +

                fieldRow('Client ID', `<input type="text" class="jp-form-input plg-f-clientId" value="${escape(p.clientId || '')}">`, '') +
                fieldRow('Client Secret', `<input type="password" class="jp-form-input plg-f-clientSecret" placeholder="${p.clientSecretRef ? 'Leave blank to keep existing secret' : ''}" autocomplete="new-password">`, '') +
                fieldRow('Scopes', `<input type="text" class="jp-form-input plg-f-scopes" value="${escape((p.scopes || []).join(', '))}" placeholder="openid, email, profile">`, 'Comma-separated. Leave blank to use the preset default.') +

                (presetDef.needsDiscoveryUrl ?
                    fieldRow('Discovery URL', `<input type="text" class="jp-form-input plg-f-discoveryUrl" value="${escape(p.discoveryUrl || '')}" placeholder="https://.../.well-known/openid-configuration">`, '') : '') +

                (presetDef.needsManualEndpoints ?
                    fieldRow('Authorize URL', `<input type="text" class="jp-form-input plg-f-authorizeUrl" value="${escape(p.authorizeUrl || '')}">`, '') +
                    fieldRow('Token URL', `<input type="text" class="jp-form-input plg-f-tokenUrl" value="${escape(p.tokenUrl || '')}">`, '') +
                    fieldRow('Userinfo URL', `<input type="text" class="jp-form-input plg-f-userinfoUrl" value="${escape(p.userinfoUrl || '')}">`, '') +
                    fieldRow('Userinfo Mapping', `<textarea class="jp-form-textarea plg-f-userinfoMapping" rows="2" placeholder='{"sub":"id","email":"primary_email"}'>${escape(p.userinfoMapping ? JSON.stringify(p.userinfoMapping) : '')}</textarea>`, 'JSON object mapping jPulse claim names to this provider\'s userinfo field names.') : '') +

                fieldRow('Linking Strategy', `<select class="jp-form-input plg-f-linkingStrategy">${linkingOptions}</select>`, 'Overrides the global default for this provider only') +
                fieldRow('Allowed Domains', `<input type="text" class="jp-form-input plg-f-allowedDomains" value="${escape((p.allowedDomains || []).join(', '))}" placeholder="corp.example.com">`, 'Comma-separated. Leave blank to allow any domain.') +
                fieldRow('JIT: Override Roles', `<label class="plg-oauth-inline-checkbox"><input type="checkbox" class="plg-f-jitRolesOverride"${p.jitRoles ? ' checked' : ''}> Users only (instead of the global default)</label>`, '') +
                fieldRow('JIT: Status', `<select class="jp-form-input plg-f-jitStatus">${statusOptions}</select>`, '') +

                fieldRow('Redirect URI', `<input type="text" class="jp-form-input plg-f-redirectUri" value="${escape(redirectUri(p.id))}" readonly> ` +
                    '<button type="button" class="jp-btn jp-btn-sm jp-btn-secondary plg-oauth-copy-btn">Copy</button>',
                    'Paste this into the identity provider\'s console as the allowed redirect/callback URI.') +

                '<div class="plg-oauth-form-actions">' +
                '<button type="button" class="jp-btn jp-btn-primary plg-oauth-save-btn">Save</button> ' +
                '<button type="button" class="jp-btn jp-btn-secondary plg-oauth-cancel-btn">Cancel</button>' +
                '<span class="plg-oauth-form-error jp-text-danger"></span>' +
                '</div>' +
                '</div>';

            // Keep the redirect URI preview live as the admin types a new id.
            if (isNew) {
                formEl.querySelector('.plg-f-id').addEventListener('input', (event) => {
                    formEl.querySelector('.plg-f-redirectUri').value = redirectUri(event.target.value.trim());
                });
            }
            formEl.querySelector('.plg-f-preset').addEventListener('change', (event) => {
                formPresetOverride = event.target.value;
                renderForm(); // preset changes which endpoint fields are shown
            });
            formEl.querySelector('.plg-oauth-copy-btn').addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(formEl.querySelector('.plg-f-redirectUri').value);
                    jPulse.UI.toast.show('Redirect URI copied to clipboard', 'success');
                } catch (error) {
                    void error; // clipboard API can be unavailable (e.g. non-HTTPS) - fail silently
                }
            });
            formEl.querySelector('.plg-oauth-cancel-btn').addEventListener('click', () => {
                editingId = null;
                formPresetOverride = null;
                render();
            });
            formEl.querySelector('.plg-oauth-save-btn').addEventListener('click', () => onSave(isNew));

            function fieldRow(label, inputHtml, help) {
                return '<div class="jp-form-group plg-oauth-field-row">' +
                    '<label class="jp-form-label">' + escape(label) + '</label>' +
                    inputHtml +
                    (help ? '<div class="jp-text-small jp-text-muted">' + help + '</div>' : '') +
                    '</div>';
            }
        }

        /** Collect the form into the stored-provider shape and POST/PUT it. */
        async function onSave(isNew) {
            const formEl = container.querySelector('.plg-oauth-form-container');
            const errorEl = formEl.querySelector('.plg-oauth-form-error');
            errorEl.textContent = '';

            const id = isNew ? formEl.querySelector('.plg-f-id').value.trim() : editingId;
            if (isNew && !id) {
                errorEl.textContent = 'Provider ID is required';
                return;
            }

            const body = {
                id,
                preset: formEl.querySelector('.plg-f-preset').value,
                label: formEl.querySelector('.plg-f-label').value.trim(),
                icon: formEl.querySelector('.plg-f-icon').value.trim(),
                buttonColor: formEl.querySelector('.plg-f-buttonColor').value,
                order: parseInt(formEl.querySelector('.plg-f-order').value, 10) || 100,
                enabled: formEl.querySelector('.plg-f-enabled').checked,
                clientId: formEl.querySelector('.plg-f-clientId').value.trim(),
                scopes: toList(formEl.querySelector('.plg-f-scopes').value),
                linkingStrategy: formEl.querySelector('.plg-f-linkingStrategy').value || null,
                allowedDomains: toList(formEl.querySelector('.plg-f-allowedDomains').value),
                jitRoles: formEl.querySelector('.plg-f-jitRolesOverride').checked ? ['user'] : null,
                jitStatus: formEl.querySelector('.plg-f-jitStatus').value || null
            };

            const discoveryUrlEl = formEl.querySelector('.plg-f-discoveryUrl');
            if (discoveryUrlEl) {
                body.discoveryUrl = discoveryUrlEl.value.trim();
            }
            const authorizeUrlEl = formEl.querySelector('.plg-f-authorizeUrl');
            if (authorizeUrlEl) {
                body.authorizeUrl = authorizeUrlEl.value.trim();
                body.tokenUrl = formEl.querySelector('.plg-f-tokenUrl').value.trim();
                body.userinfoUrl = formEl.querySelector('.plg-f-userinfoUrl').value.trim();
                const mappingText = formEl.querySelector('.plg-f-userinfoMapping').value.trim();
                if (mappingText) {
                    try {
                        body.userinfoMapping = JSON.parse(mappingText);
                    } catch (error) {
                        errorEl.textContent = 'Userinfo Mapping must be valid JSON';
                        return;
                    }
                }
            }

            const clientSecret = formEl.querySelector('.plg-f-clientSecret').value;
            if (clientSecret) {
                body.clientSecret = clientSecret;
            }

            const saveBtn = formEl.querySelector('.plg-oauth-save-btn');
            saveBtn.disabled = true;
            try {
                const response = isNew ?
                    await jPulse.api.post('/api/1/auth-oauth/admin/providers', body) :
                    await jPulse.api.put(`/api/1/auth-oauth/admin/providers/${encodeURIComponent(id)}`, body);

                if (!response.success) {
                    errorEl.textContent = response.error || 'Failed to save provider';
                    saveBtn.disabled = false;
                    return;
                }

                if (isNew) {
                    providers.push(response.data);
                } else {
                    providers = providers.map(existing => (existing.id === id ? response.data : existing));
                }
                ctx.onChange(providers);
                editingId = null;
                formPresetOverride = null;
                jPulse.UI.toast.show(isNew ? 'Provider added' : 'Provider updated', 'success');
                render();
            } catch (error) {
                errorEl.textContent = 'Network error - please try again';
                saveBtn.disabled = false;
            }
        }

        async function onDelete(id) {
            const result = await jPulse.UI.confirmDialog({
                title: 'Delete Provider',
                message: `Delete provider "${id}"? Users who signed in via this provider will no longer be able to use it.`,
                buttons: ['Cancel', 'Delete']
            });
            if (!result.confirmed) {
                return;
            }

            try {
                const response = await jPulse.api.delete(`/api/1/auth-oauth/admin/providers/${encodeURIComponent(id)}`);
                if (!response.success) {
                    jPulse.UI.toast.show(response.error || 'Failed to delete provider', 'error');
                    return;
                }
                providers = providers.filter(p => p.id !== id);
                ctx.onChange(providers);
                jPulse.UI.toast.show('Provider deleted', 'success');
                render();
            } catch (error) {
                jPulse.UI.toast.show('Network error - please try again', 'error');
            }
        }

        async function onTest(id, btn) {
            const originalText = btn.textContent;
            btn.textContent = 'Testing...';
            btn.disabled = true;
            try {
                const response = await jPulse.api.post(`/api/1/auth-oauth/admin/providers/${encodeURIComponent(id)}/test`);
                if (!response.success) {
                    jPulse.UI.toast.show(response.error || 'Connection test failed', 'error');
                } else {
                    jPulse.UI.toast.show(`Connection OK - issuer: ${response.data.issuer}`, 'success');
                }
            } catch (error) {
                jPulse.UI.toast.show('Network error - please try again', 'error');
            } finally {
                btn.textContent = originalText;
                btn.disabled = false;
            }
        }
    }
};

// EOF plugins/auth-oauth/webapp/view/jpulse-common.js
