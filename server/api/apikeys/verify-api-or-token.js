'use strict';

const authJwt = require('../jwt-helper');
const externalAuth = require('../external-auth');

/**
 * Middleware that accepts either JWT (x-access-token) or API key (x-api-key).
 * API key takes precedence. When externalAuth is enabled, the token is verified
 * by the external system verification API instead of the local JWT.
 * It is active only when security is enabled.
 * @param {*} runtime the runtime
 * @param {*} opts { allowAnon: true } let the request pass without a valid token (only public data)
 */
module.exports = function verifyApiOrToken(runtime, opts) {
    const allowAnon = !!opts?.allowAnon;
    return async function (req, res, next) {
        if (!runtime?.settings?.secureEnabled) {
            return next();
        }

        const apiKey = req.headers['x-api-key'];
        if (apiKey) {
            try {
                const stored = await runtime.apiKeys.getApiKeys();
                const now = Date.now();
                const validKey = stored.find(k => {
                    if (!k || k.key !== apiKey || k.enabled === false) {
                        return false;
                    }
                    if (!k.expires) {
                        return true;
                    }
                    const expiresAt = new Date(k.expires).getTime();
                    return !isNaN(expiresAt) && expiresAt > now;
                });

                if (validKey) {
                    req.apiKey = validKey;
                    // Grant admin group to match existing authorization checks.
                    req.userId = validKey.id || `apikey:${apiKey}`;
                    req.userGroups = authJwt.adminGroups[0];
                    return next();
                }
            } catch (err) {
                runtime.logger.error(`api-key validation failed: ${err}`);
                return res.status(500).json({ error: 'unexpected_error', message: 'ApiKey validation failed' });
            }
            return res.status(401).json({ error: 'unauthorized_error', message: 'Invalid API Key' });
        }

        const extAuth = runtime.settings.externalAuth;
        if (extAuth?.enabled) {
            const token = externalAuth.cookieToken(req, extAuth.cookieName) || req.headers['x-access-token'];
            if (!token) {
                if (allowAnon) {
                    req.userId = null;
                    req.userGroups = undefined;
                    return next();
                }
                return res.status(401).json({ error: 'unauthorized_error', message: 'Authentication required!' });
            }
            try {
                const user = await externalAuth.verifyExternalToken(runtime.settings, token);
                req.userId = user.id;
                req.userGroups = user.groups;
                req.isAuthenticated = true;
                return next();
            } catch (err) {
                runtime.logger?.warn(`external auth verify failed: ${err}`);
                if (allowAnon) {
                    req.userId = null;
                    req.userGroups = undefined;
                    return next();
                }
                return res.status(401).json({ error: 'unauthorized_error', message: 'Invalid token!' });
            }
        }

        return authJwt.verifyToken(req, res, next);
    };
};
