/*
 * @name            jPulse Framework / Plugins / Auth-OAuth / WebApp / View / jPulse Navigation
 * @tagline         Navigation of the Auth-OAuth Plugin
 * @description     Navigation for the Auth-OAuth Plugin, appended to the framework navigation
 * @file            plugins/auth-oauth/webapp/view/jpulse-navigation.js
 * @version         1.0.1
 * @release         2026-07-31
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

// Add Auth-OAuth to jPulse Plugins section
if (window.jPulseNavigation?.site?.jPulsePlugins) {
    window.jPulseNavigation.site.jPulsePlugins.pages.authOauth = {
        label: 'Connected Accounts',
        url: '/jpulse-plugins/auth-oauth.shtml',
        icon: '🔑'
    };
}

// EOF plugins/auth-oauth/webapp/view/jpulse-navigation.js
