import express from "express";
import pg from "pg";

const { Pool } = pg;

export function createApiApp(configuration = process.env, dependencies = {}) {
  const app = express();
  app.disable("x-powered-by");

  const connectionString = nonEmpty(configuration.DATABASE_URL);
  const pool = dependencies.pool ?? (connectionString ? new Pool({ connectionString }) : null);

  app.get("/healthz", (_request, response) => {
    response.json({ status: "ok", service: "api" });
  });

  app.get("/db/ready", async (_request, response) => {
    if (!pool) {
      return response.status(503).json({ status: "unavailable", database: "postgres" });
    }

    try {
      const result = await pool.query("SELECT 1 AS ready");
      if (result.rows?.[0]?.ready !== 1) throw new Error("Unexpected readiness result.");
      response.json({ status: "ok", database: "postgres" });
    } catch {
      response.status(503).json({ status: "unavailable", database: "postgres" });
    }
  });

  app.get("/topology", (_request, response) => {
    response.json({
      service: "api",
      webPublicUrlAvailable: Boolean(nonEmpty(configuration.WEB_URL)),
      webInternalUrlAvailable: Boolean(nonEmpty(configuration.WEB_INTERNAL_URL))
    });
  });

  app.use((_request, response) => {
    response.sendStatus(404);
  });

  app.locals.closeResources = async () => {
    if (pool && typeof pool.end === "function") await pool.end();
  };

  return app;
}

function nonEmpty(value) {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}
