/*
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / View / jPulse Navigation
 * @tagline         Navigation of the Auth-OAuth Plugin
 * @description     Navigation for the Auth-OAuth Plugin, appended to the framework navigation
 * @file            plugins/auth-oauth/webapp/view/jpulse-navigation.js
 * @version         1.0.5
 * @release         2026-09-30
 * @repository      https://github.com/jpulse-net/plugin-auth-oauth
 * @author          Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @copyright       2025-2026 Peter Thoeny, https://twiki.org & https://github.com/peterthoeny/
 * @license         BSL 1.1 -- see LICENSE file; for commercial use: team@jpulse.net
 * @genai           80%, Cursor 3.12, Claude Sonnet 5
 */

/**
 * Auth-OAuth Plugin - Navigation Integration
 * This file is appended to framework navigation (W-098 append mode)
 */

// Same shield as plugin.json. Navigation inserts a string that starts with <svg as HTML.
const AUTH_OAUTH_ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /><circle cx="12" cy="10" r="2" /><path d="M12 12v4" /></svg>';

// Add Auth-OAuth to jPulse Plugins section
if (window.jPulseNavigation?.site?.jPulsePlugins) {
    window.jPulseNavigation.site.jPulsePlugins.pages.authOauth = {
        label: 'Connected Accounts',
        url: '/jpulse-plugins/auth-oauth.shtml',
        icon: AUTH_OAUTH_ICON
    };
}

// EOF plugins/auth-oauth/webapp/view/jpulse-navigation.js
