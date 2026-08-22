import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import session from "express-session";
import { createWebApp } from "../src/app.mjs";
import {
  createOfficialOidcProtocol,
  readVibeNestAuthSettings
} from "../src/vibenest-auth.mjs";

const AUTH_CONFIGURATION = Object.freeze({
  VIBENEST_AUTH_ENABLED: "true",
  VIBENEST_AUTH_ISSUER: "https://vibenest.example",
  VIBENEST_AUTH_CLIENT_ID: "qa-fixture-client",
  VIBENEST_AUTH_CLIENT_SECRET: "not-a-real-secret-used-only-by-tests",
  VIBENEST_AUTH_REDIRECT_URI: "https://fixture.example/auth/vibenest/callback"
});

test("the official adapter requests code flow with S256 PKCE and validates the callback", async () => {
  const calls = [];
  const clientConfiguration = { marker: "discovered-client" };
  const library = {
    async discovery(issuer, clientId, clientSecret) {
      calls.push(["discovery", issuer.href, clientId, clientSecret]);
      return clientConfiguration;
    },
    randomPKCECodeVerifier: () => "v".repeat(48),
    randomState: () => "s".repeat(32),
    randomNonce: () => "n".repeat(32),
    async calculatePKCECodeChallenge(verifier) {
      calls.push(["challenge", verifier]);
      return "c".repeat(43);
    },
    buildAuthorizationUrl(configuration, parameters) {
      calls.push(["authorize", configuration, parameters]);
      return new URL("https://vibenest.example/connect/authorize?request=bounded");
    },
    async authorizationCodeGrant(configuration, currentUrl, checks) {
      calls.push(["grant", configuration, currentUrl.href, checks]);
      return { claims: () => ({ sub: "pairwise-subject" }) };
    }
  };
  const settings = readVibeNestAuthSettings(AUTH_CONFIGURATION);
  const protocol = await createOfficialOidcProtocol(settings, library);
  const attempt = await protocol.createLoginAttempt();

  assert.equal(attempt.url.protocol, "https:");
  assert.deepEqual(attempt.pending, {
    codeVerifier: "v".repeat(48),
    state: "s".repeat(32),
    nonce: "n".repeat(32)
  });
  const authorize = calls.find(call => call[0] === "authorize")[2];
  assert.deepEqual(authorize, {
    redirect_uri: AUTH_CONFIGURATION.VIBENEST_AUTH_REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email",
    code_challenge: "c".repeat(43),
    code_challenge_method: "S256",
    state: "s".repeat(32),
    nonce: "n".repeat(32)
  });

  const callback = new URL(`${AUTH_CONFIGURATION.VIBENEST_AUTH_REDIRECT_URI}?code=one-time&state=${"s".repeat(32)}`);
  assert.deepEqual(await protocol.redeemAuthorizationResponse(callback, attempt.pending), {
    sub: "pairwise-subject"
  });
  const grant = calls.find(call => call[0] === "grant");
  assert.equal(grant[1], clientConfiguration);
  assert.equal(grant[2], callback.href);
  assert.deepEqual(grant[3], {
    pkceCodeVerifier: "v".repeat(48),
    expectedState: "s".repeat(32),
    expectedNonce: "n".repeat(32),
    idTokenExpected: true
  });
});

test("pending login survives an application restart and callback ignores forged proxy origins", async () => {
  const store = new session.MemoryStore();
  const firstProtocol = createTestProtocol();
  const firstApp = await createWebApp(AUTH_CONFIGURATION, {
    oidcProtocol: firstProtocol,
    sessionStore: store,
    secureCookies: false
  });

  let loginCookie;
  let state;
  await withServer(firstApp, async origin => {
    const login = await fetch(`${origin}/auth/vibenest/login`, { redirect: "manual" });
    assert.equal(login.status, 303);
    const authorizationUrl = new URL(login.headers.get("location"));
    assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
    state = authorizationUrl.searchParams.get("state");
    loginCookie = responseCookie(login);
    const setCookie = login.headers.get("set-cookie");
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /SameSite=Lax/i);
  });

  const secondProtocol = createTestProtocol();
  const secondApp = await createWebApp(AUTH_CONFIGURATION, {
    oidcProtocol: secondProtocol,
    sessionStore: store,
    secureCookies: false
  });
  await withServer(secondApp, async origin => {
    const callback = await fetch(`${origin}/auth/vibenest/callback?code=valid&state=${state}`, {
      redirect: "manual",
      headers: {
        cookie: loginCookie,
        "x-forwarded-host": "attacker.invalid",
        "x-forwarded-proto": "http"
      }
    });
    assert.equal(callback.status, 303);
    assert.equal(callback.headers.get("location"), "https://fixture.example/");
    const callbackUrl = secondProtocol.redeemCalls[0].currentUrl;
    assert.equal(callbackUrl.origin, "https://fixture.example");
    assert.equal(callbackUrl.pathname, "/auth/vibenest/callback");
    assert.equal(callbackUrl.searchParams.get("code"), "valid");

    const authenticatedCookie = responseCookie(callback);
    const protectedResponse = await fetch(`${origin}/protected`, {
      headers: { cookie: authenticatedCookie }
    });
    assert.equal(protectedResponse.status, 200);
    assert.deepEqual(await protectedResponse.json(), { authenticated: true });

    const home = await fetch(`${origin}/`, { headers: { cookie: authenticatedCookie } });
    const homeBody = await home.text();
    assert.match(homeBody, /id="auth-status">Signed in/);
    assert.doesNotMatch(homeBody, /pairwise-subject/);
    const csrfToken = homeBody.match(/name="_csrf" value="([^"]+)"/)?.[1];
    assert.ok(csrfToken);

    const noCsrf = await fetch(`${origin}/auth/logout`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie: authenticatedCookie, origin: "https://fixture.example" }
    });
    assert.equal(noCsrf.status, 403);

    const forgedOrigin = await logoutRequest(origin, authenticatedCookie, csrfToken, "https://attacker.invalid");
    assert.equal(forgedOrigin.status, 403);

    const logout = await logoutRequest(origin, authenticatedCookie, csrfToken, "https://fixture.example");
    assert.equal(logout.status, 303);
    assert.equal(logout.headers.get("location"), "https://fixture.example/");
    assert.match(logout.headers.get("set-cookie"), /Expires=Thu, 01 Jan 1970/i);

    const afterLogout = await fetch(`${origin}/protected`, {
      headers: { cookie: authenticatedCookie }
    });
    assert.equal(afterLogout.status, 401);
  });
});

test("invalid callback validation is one-shot and never exposes provider details", async () => {
  const protocol = createTestProtocol({ callbackError: new Error("invalid signature: sensitive provider detail") });
  const app = await createWebApp(AUTH_CONFIGURATION, {
    oidcProtocol: protocol,
    sessionStore: new session.MemoryStore(),
    secureCookies: false
  });

  await withServer(app, async origin => {
    const login = await fetch(`${origin}/auth/vibenest/login`, { redirect: "manual" });
    const cookie = responseCookie(login);
    const state = new URL(login.headers.get("location")).searchParams.get("state");
    const rejected = await fetch(`${origin}/auth/vibenest/callback?code=invalid&state=${state}`, {
      redirect: "manual",
      headers: { cookie }
    });
    const rejectedBody = await rejected.text();
    assert.equal(rejected.status, 401);
    assert.doesNotMatch(rejectedBody, /signature|provider|detail/i);

    const replay = await fetch(`${origin}/auth/vibenest/callback?code=valid&state=${state}`, {
      redirect: "manual",
      headers: { cookie }
    });
    assert.equal(replay.status, 400);
  });
});

test("expired login state and browser-authored identities fail closed", async () => {
  let currentTime = 1_000;
  const protocol = createTestProtocol();
  const app = await createWebApp(AUTH_CONFIGURATION, {
    oidcProtocol: protocol,
    sessionStore: new session.MemoryStore(),
    secureCookies: false,
    now: () => currentTime
  });

  await withServer(app, async origin => {
    const unauthenticated = await fetch(`${origin}/protected?userId=forged`, {
      headers: { "x-vibenest-user-id": "forged" }
    });
    assert.equal(unauthenticated.status, 401);

    const login = await fetch(`${origin}/auth/vibenest/login`, { redirect: "manual" });
    const cookie = responseCookie(login);
    const state = new URL(login.headers.get("location")).searchParams.get("state");
    currentTime += 5 * 60 * 1000 + 1;
    const expired = await fetch(`${origin}/auth/vibenest/callback?code=valid&state=${state}`, {
      redirect: "manual",
      headers: { cookie }
    });
    assert.equal(expired.status, 400);
    assert.equal(protocol.redeemCalls.length, 0);
  });
});

test("enabled Auth rejects incomplete or unsafe server configuration", async () => {
  assert.deepEqual(readVibeNestAuthSettings({}), { enabled: false });
  await assert.rejects(
    createWebApp({ VIBENEST_AUTH_ENABLED: "true" }),
    /VIBENEST_AUTH_ISSUER is required/
  );
  await assert.rejects(
    createWebApp({
      ...AUTH_CONFIGURATION,
      VIBENEST_AUTH_ISSUER: "http://vibenest.example"
    }),
    /absolute HTTPS URL/
  );
  await assert.rejects(
    createWebApp({
      ...AUTH_CONFIGURATION,
      VIBENEST_AUTH_REDIRECT_URI: "https://fixture.example/wrong-callback"
    }),
    /exact HTTPS \/auth\/vibenest\/callback/
  );
  await assert.rejects(
    createWebApp(AUTH_CONFIGURATION, { oidcProtocol: createTestProtocol() }),
    /DATABASE_URL is required/
  );

  const app = await createWebApp(AUTH_CONFIGURATION, {
    oidcProtocol: createTestProtocol(),
    sessionStore: new session.MemoryStore()
  });
  await withServer(app, async origin => {
    const login = await fetch(`${origin}/auth/vibenest/login`, {
      redirect: "manual",
      headers: { "x-forwarded-proto": "https" }
    });
    assert.match(login.headers.get("set-cookie"), /Secure/i);
    assert.match(login.headers.get("set-cookie"), /HttpOnly/i);
    assert.match(login.headers.get("set-cookie"), /SameSite=Lax/i);
  });
});

function createTestProtocol({ callbackError } = {}) {
  const state = "state-".padEnd(32, "s");
  const nonce = "nonce-".padEnd(32, "n");
  const codeVerifier = "verifier-".padEnd(48, "v");
  const redeemCalls = [];
  return {
    redeemCalls,
    async createLoginAttempt() {
      const url = new URL("https://vibenest.example/connect/authorize");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("code_challenge", "challenge".padEnd(43, "c"));
      url.searchParams.set("code_challenge_method", "S256");
      url.searchParams.set("state", state);
      url.searchParams.set("nonce", nonce);
      return { url, pending: { codeVerifier, state, nonce } };
    },
    async redeemAuthorizationResponse(currentUrl, pending) {
      redeemCalls.push({ currentUrl, pending });
      if (callbackError) throw callbackError;
      if (currentUrl.searchParams.get("state") !== pending.state) throw new Error("wrong state");
      return { sub: "pairwise-subject" };
    }
  };
}

async function logoutRequest(origin, cookie, csrfToken, requestOrigin) {
  return fetch(`${origin}/auth/logout`, {
    method: "POST",
    redirect: "manual",
    headers: {
      cookie,
      origin: requestOrigin,
      "content-type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({ _csrf: csrfToken })
  });
}

function responseCookie(response) {
  const value = response.headers.get("set-cookie");
  assert.ok(value, "response must set the opaque application-session cookie");
  return value.split(";", 1)[0];
}

async function withServer(app, work) {
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  try {
    await work(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await app.locals.closeResources();
  }
}
