import { createHash } from "node:crypto";
import connectPgSimple from "connect-pg-simple";
import { csrfSync } from "csrf-sync";
import express from "express";
import session from "express-session";
import * as oidc from "openid-client";
import pg from "pg";

const { Pool } = pg;
const PgSessionStore = connectPgSimple(session);

const CALLBACK_PATH = "/auth/vibenest/callback";
const LOGIN_PATH = "/auth/vibenest/login";
const LOGOUT_PATH = "/auth/logout";
const LOGIN_ATTEMPT_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_COOKIE_NAME = "vn_fixture_session";

export function readVibeNestAuthSettings(configuration = process.env) {
  const enabledValue = optionalValue(configuration.VIBENEST_AUTH_ENABLED)?.toLowerCase();
  if (enabledValue === undefined || enabledValue === "false") return { enabled: false };
  if (enabledValue !== "true") {
    throw new Error("VIBENEST_AUTH_ENABLED must be true or false.");
  }

  const issuer = exactHttpsUrl(requiredValue(configuration, "VIBENEST_AUTH_ISSUER"), "VIBENEST_AUTH_ISSUER");
  if (issuer.username || issuer.password || issuer.search || issuer.hash || !["", "/"].includes(issuer.pathname)) {
    throw new Error("VIBENEST_AUTH_ISSUER must be an HTTPS origin without credentials, path, query, or fragment.");
  }
  issuer.pathname = "/";

  const redirectUri = exactHttpsUrl(
    requiredValue(configuration, "VIBENEST_AUTH_REDIRECT_URI"),
    "VIBENEST_AUTH_REDIRECT_URI"
  );
  if (
    redirectUri.username
    || redirectUri.password
    || redirectUri.pathname !== CALLBACK_PATH
    || redirectUri.search
    || redirectUri.hash
  ) {
    throw new Error(`VIBENEST_AUTH_REDIRECT_URI must be an exact HTTPS ${CALLBACK_PATH} URL.`);
  }

  return {
    enabled: true,
    issuer,
    clientId: requiredValue(configuration, "VIBENEST_AUTH_CLIENT_ID"),
    clientSecret: requiredValue(configuration, "VIBENEST_AUTH_CLIENT_SECRET"),
    redirectUri,
    applicationOrigin: new URL("/", redirectUri)
  };
}

export async function createOfficialOidcProtocol(settings, oidcLibrary = oidc) {
  const clientConfiguration = await oidcLibrary.discovery(
    settings.issuer,
    settings.clientId,
    settings.clientSecret
  );

  return {
    async createLoginAttempt() {
      const codeVerifier = oidcLibrary.randomPKCECodeVerifier();
      const state = oidcLibrary.randomState();
      const nonce = oidcLibrary.randomNonce();
      const codeChallenge = await oidcLibrary.calculatePKCECodeChallenge(codeVerifier);
      const url = oidcLibrary.buildAuthorizationUrl(clientConfiguration, {
        redirect_uri: settings.redirectUri.href,
        response_type: "code",
        scope: "openid profile email",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        nonce
      });

      return {
        url,
        pending: { codeVerifier, state, nonce }
      };
    },

    async redeemAuthorizationResponse(currentUrl, pending) {
      const tokens = await oidcLibrary.authorizationCodeGrant(clientConfiguration, currentUrl, {
        pkceCodeVerifier: pending.codeVerifier,
        expectedState: pending.state,
        expectedNonce: pending.nonce,
        idTokenExpected: true
      });
      return tokens.claims();
    }
  };
}

export async function installVibeNestAuth(app, configuration = process.env, dependencies = {}) {
  const settings = readVibeNestAuthSettings(configuration);
  if (!settings.enabled) {
    return {
      enabled: false,
      close: async () => {},
      generateCsrfToken: () => null,
      requireUser: (_request, response) => response.sendStatus(401)
    };
  }

  const protocol = dependencies.oidcProtocol ?? await createOfficialOidcProtocol(settings);
  const sessionResources = createSessionResources(configuration, dependencies);
  const secureCookies = dependencies.secureCookies ?? true;
  const sessionMiddleware = session({
    name: SESSION_COOKIE_NAME,
    secret: deriveSessionSecret(settings.clientSecret, settings.clientId),
    store: sessionResources.store,
    resave: false,
    saveUninitialized: false,
    rolling: false,
    cookie: {
      httpOnly: true,
      secure: secureCookies,
      sameSite: "lax",
      maxAge: SESSION_TTL_MS,
      path: "/"
    }
  });
  const { generateToken, csrfSynchronisedProtection } = csrfSync({
    getTokenFromRequest(request) {
      const formToken = request.body?._csrf;
      if (typeof formToken === "string") return formToken;
      const headerToken = request.get("x-csrf-token");
      return typeof headerToken === "string" ? headerToken : null;
    }
  });
  const now = dependencies.now ?? (() => Date.now());

  app.set("trust proxy", 1);
  app.use(sessionMiddleware);
  app.use(LOGOUT_PATH, express.urlencoded({ extended: false, limit: "4kb", parameterLimit: 8 }));

  app.get(LOGIN_PATH, noStore, async (request, response, next) => {
    try {
      const attempt = await protocol.createLoginAttempt();
      if (!isLoginAttempt(attempt)) throw new Error("The OIDC client returned an invalid login attempt.");
      request.session.oidc = {
        ...attempt.pending,
        expiresAt: now() + LOGIN_ATTEMPT_TTL_MS
      };
      await saveSession(request);
      response.redirect(303, attempt.url.href);
    } catch (error) {
      next(error);
    }
  });

  app.get(CALLBACK_PATH, noStore, async (request, response) => {
    const pending = request.session.oidc;
    delete request.session.oidc;
    try {
      await saveSession(request);
      if (!isPendingLogin(pending) || pending.expiresAt < now()) {
        return response.sendStatus(400);
      }

      // Absolute-form request origins and proxy headers are untrusted. Only copy the
      // authorization response query onto the exact configured callback URL.
      const receivedUrl = new URL(request.originalUrl, "http://request.invalid");
      const currentUrl = new URL(settings.redirectUri);
      currentUrl.search = receivedUrl.search;
      const claims = await protocol.redeemAuthorizationResponse(currentUrl, pending);
      if (!isValidSubject(claims?.sub)) return response.sendStatus(401);

      await regenerateSession(request);
      request.session.user = { subject: claims.sub };
      await saveSession(request);
      return response.redirect(303, settings.applicationOrigin.href);
    } catch {
      return response.sendStatus(401);
    }
  });

  const requireUser = (request, response, next) => {
    if (!isValidSubject(request.session?.user?.subject)) return response.sendStatus(401);
    return next();
  };

  app.post(
    LOGOUT_PATH,
    noStore,
    requireExactOrigin(settings.applicationOrigin.origin),
    csrfSynchronisedProtection,
    (request, response, next) => {
      request.session.destroy(error => {
        if (error) return next(error);
        response.clearCookie(SESSION_COOKIE_NAME, {
          httpOnly: true,
          secure: secureCookies,
          sameSite: "lax",
          path: "/"
        });
        return response.redirect(303, settings.applicationOrigin.href);
      });
    }
  );

  return {
    enabled: true,
    close: sessionResources.close,
    generateCsrfToken: generateToken,
    requireUser
  };
}

function createSessionResources(configuration, dependencies) {
  if (dependencies.sessionStore) {
    return { store: dependencies.sessionStore, close: async () => {} };
  }

  const connectionString = requiredValue(configuration, "DATABASE_URL");
  const pool = new Pool({ connectionString, max: 4 });
  const store = new PgSessionStore({
    pool,
    tableName: "vibenest_auth_sessions",
    createTableIfMissing: true,
    pruneSessionInterval: 60
  });
  return {
    store,
    close: async () => pool.end()
  };
}

function deriveSessionSecret(clientSecret, clientId) {
  return createHash("sha256")
    .update("vibenest-auth-express-session-v1\0", "utf8")
    .update(clientId, "utf8")
    .update("\0", "utf8")
    .update(clientSecret, "utf8")
    .digest("base64url");
}

function requireExactOrigin(expectedOrigin) {
  return (request, response, next) => {
    if (request.get("origin") !== expectedOrigin) return response.sendStatus(403);
    return next();
  };
}

function noStore(_request, response, next) {
  response.set("Cache-Control", "no-store");
  response.set("Referrer-Policy", "no-referrer");
  next();
}

function isLoginAttempt(attempt) {
  return attempt
    && attempt.url instanceof URL
    && attempt.url.protocol === "https:"
    && isPendingLogin({ ...attempt.pending, expiresAt: Date.now() });
}

function isPendingLogin(value) {
  return value
    && isBoundedString(value.codeVerifier, 32, 512)
    && isBoundedString(value.state, 16, 512)
    && isBoundedString(value.nonce, 16, 512)
    && Number.isFinite(value.expiresAt);
}

function isValidSubject(value) {
  return isBoundedString(value, 1, 512);
}

function isBoundedString(value, minimum, maximum) {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum;
}

function saveSession(request) {
  return new Promise((resolve, reject) => {
    request.session.save(error => error ? reject(error) : resolve());
  });
}

function regenerateSession(request) {
  return new Promise((resolve, reject) => {
    request.session.regenerate(error => error ? reject(error) : resolve());
  });
}

function requiredValue(configuration, name) {
  const value = optionalValue(configuration[name]);
  if (value === undefined) throw new Error(`${name} is required when VibeNest Auth is enabled.`);
  return value;
}

function optionalValue(value) {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function exactHttpsUrl(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL.`);
  }
  if (url.protocol !== "https:") throw new Error(`${name} must be an absolute HTTPS URL.`);
  return url;
}
