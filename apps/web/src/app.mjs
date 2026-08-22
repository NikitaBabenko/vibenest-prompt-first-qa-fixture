import express from "express";

export const APP_MARKER = "vibenest-prompt-first-qa";

export function createWebApp(configuration = process.env) {
  const app = express();
  app.disable("x-powered-by");

  app.get("/", (_request, response) => {
    response
      .type("html")
      .send(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VibeNest QA Fixture</title></head>
<body><main><h1>VibeNest QA Fixture</h1><p id="fixture-marker">${APP_MARKER}</p><nav><a href="/healthz">Health</a> <a href="/meta">Build metadata</a></nav></main></body>
</html>`);
  });

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

  app.get("/protected", (_request, response) => {
    response.sendStatus(401);
  });

  app.use((_request, response) => {
    response.sendStatus(404);
  });

  return app;
}

function isNonEmpty(value) {
  return typeof value === "string" && value.trim().length > 0;
}
