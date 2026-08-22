import express from "express";
import { installVibeNestAuth } from "./vibenest-auth.mjs";

export const APP_MARKER = "vibenest-prompt-first-qa";

export async function createWebApp(configuration = process.env, dependencies = {}) {
  const app = express();
  app.disable("x-powered-by");

  app.get("/healthz", (_request, response) => {
    response.json({ status: "ok", service: "web" });
  });

  app.get("/meta", (_request, response) => {
    response.json({
      service: "web",
      sourceCommitAvailable: isNonEmpty(configuration.SOURCE_COMMIT),
      uptimeSeconds: Math.floor(process.uptime())
    });
  });

  app.get("/topology", (_request, response) => {
    response.json({
      service: "web",
      apiPublicUrlAvailable: isNonEmpty(configuration.API_URL),
      apiInternalUrlAvailable: isNonEmpty(configuration.API_INTERNAL_URL)
    });
  });

  const auth = await installVibeNestAuth(app, configuration, dependencies);

  app.get("/", (request, response) => {
    response.set("Cache-Control", "no-store");
    response.set("Referrer-Policy", "no-referrer");
    const signedIn = Boolean(request.session?.user?.subject);
    const authControls = auth.enabled
      ? signedIn
        ? `<p id="auth-status">Signed in</p>
<nav><a href="/protected">Protected route</a></nav>
<form method="post" action="/auth/logout"><input type="hidden" name="_csrf" value="${escapeHtml(auth.generateCsrfToken(request))}"><button type="submit">Sign out</button></form>`
        : `<p id="auth-status">Signed out</p><a href="/auth/vibenest/login">Sign in with VibeNest</a>`
      : `<p id="auth-status">Authentication is not configured</p>`;

    response
      .type("html")
      .send(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VibeNest QA Fixture</title></head>
<body><main><h1>VibeNest QA Fixture</h1><p id="fixture-marker">${APP_MARKER}</p><nav><a href="/healthz">Health</a> <a href="/meta">Build metadata</a></nav>${authControls}</main></body>
</html>`);
  });

  app.get("/protected", auth.requireUser, (_request, response) => {
    response.set("Cache-Control", "no-store");
    response.json({ authenticated: true });
  });

  app.use((_request, response) => {
    response.sendStatus(404);
  });

  app.use((error, _request, response, _next) => {
    if (error?.code === "EBADCSRFTOKEN") return response.sendStatus(403);
    return response.sendStatus(500);
  });

  app.locals.closeResources = auth.close;

  return app;
}

function isNonEmpty(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
