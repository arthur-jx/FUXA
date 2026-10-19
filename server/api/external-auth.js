/**
 * External authentication support.
 *
 * Delegates the token verification to an external system API instead of the
 * local JWT verification. The token is taken from a shared cookie (same domain
 * reverse proxy deployment) or from the 'x-access-token' header.
 *
 * Settings (server settings):
 *  externalAuth: {
 *      enabled: true,
 *      cookieName: 'access_token',          // cookie that contains the token
 *      verifyUrl: 'https://host/api/user/me', // GET endpoint that verifies the token
 *      tokenHeader: 'Authorization',        // header used to send the token to verifyUrl
 *      tokenPrefix: 'Bearer ',              // prefix prepended to the token value
 *      usernameField: 'username',           // field (dot path) of the username in the response
 *      groupsField: 'roles',                // field (dot path) of the roles/groups in the response
 *      adminRoles: ['admin'],               // roles that map to the FUXA admin group (-1)
 *      cacheTtl: 300,                       // verification result cache in seconds
 *      loginPageUrl: 'https://host/login?redirect={url}' // login page of the external system
 *  }
 */
'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');

const authJwt = require('./jwt-helper');

const REQUEST_TIMEOUT = 10000; // 10 seconds
// token -> { id, groups, expires }
const verifyCache = new Map();

/**
 * Resolve a dot path field ('data.user.name') from an object
 */
function getFieldValue(obj, path) {
    if (!path || !obj) {
        return undefined;
    }
    return path.split('.').reduce((current, key) => {
        return (current == null) ? undefined : current[key];
    }, obj);
}

function toRoleList(roles) {
    if (Array.isArray(roles)) {
        return roles.filter(r => r != null && r !== '').map(r => String(r));
    }
    if (roles != null && roles !== '') {
        return String(roles).split(',').map(r => r.trim()).filter(r => r);
    }
    return [];
}

/**
 * Map the external roles to the FUXA user groups.
 * Roles listed in adminRoles map to the FUXA admin group (-1).
 */
function mapGroups(roles, adminRoles) {
    const roleList = toRoleList(roles);
    const adminList = Array.isArray(adminRoles) ? adminRoles : toRoleList(adminRoles);
    if (adminList.length && adminList.some(role => roleList.indexOf(role) !== -1)) {
        return authJwt.adminGroups[0];
    }
    return roleList;
}

/**
 * Extract the token value from the request cookies
 */
function cookieToken(req, cookieName) {
    const cookies = req?.headers?.cookie;
    if (!cookies || !cookieName) {
        return null;
    }
    const found = cookies.split(';').map(c => c.trim()).find(c => c.startsWith(cookieName + '='));
    return found ? decodeURIComponent(found.substring(cookieName.length + 1)) : null;
}

/**
 * Call the external verification API (GET) with the token.
 * @param {*} settings the server settings (settings.externalAuth)
 * @param {*} token the token to verify
 * @returns {Promise<{id, groups}>} the mapped user info
 */
function verifyExternalToken(settings, token) {
    return new Promise((resolve, reject) => {
        const extAuth = settings?.externalAuth;
        if (!extAuth?.verifyUrl) {
            return reject(new Error('externalAuth.verifyUrl is not configured'));
        }
        const cached = verifyCache.get(token);
        if (cached && cached.expires > Date.now()) {
            return resolve({ id: cached.id, groups: cached.groups });
        }
        let verifyUrl;
        try {
            verifyUrl = new URL(extAuth.verifyUrl);
        } catch (err) {
            return reject(new Error('externalAuth.verifyUrl is invalid: ' + err.message));
        }
        const transport = (verifyUrl.protocol === 'https:') ? https : http;
        const headers = {};
        headers[extAuth.tokenHeader || 'Authorization'] = (extAuth.tokenPrefix || '') + token;
        const request = transport.get(verifyUrl, { headers, timeout: REQUEST_TIMEOUT }, (response) => {
            let data = '';
            response.on('data', chunk => data += chunk);
            response.on('end', () => {
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    return reject(new Error('verify token failed with status ' + response.statusCode));
                }
                try {
                    const body = JSON.parse(data);
                    const username = getFieldValue(body, extAuth.usernameField || 'username');
                    if (username == null || username === '') {
                        return reject(new Error('verify token response has no username (field: ' + (extAuth.usernameField || 'username') + ')'));
                    }
                    const groups = mapGroups(getFieldValue(body, extAuth.groupsField), extAuth.adminRoles);
                    const user = { id: String(username), groups: groups };
                    const ttl = (parseInt(extAuth.cacheTtl) > 0 ? parseInt(extAuth.cacheTtl) : 300) * 1000;
                    verifyCache.set(token, { id: user.id, groups: user.groups, expires: Date.now() + ttl });
                    return resolve(user);
                } catch (err) {
                    return reject(new Error('verify token response is not a valid JSON: ' + err.message));
                }
            });
        });
        request.on('timeout', () => {
            request.destroy(new Error('verify token request timeout'));
        });
        request.on('error', err => reject(err));
    });
}

module.exports = {
    cookieToken: cookieToken,
    verifyExternalToken: verifyExternalToken
};
