import { pathToFileURL } from "node:url";
import { createWebApp } from "./app.mjs";

export const CRASH_MARKER = "QA_FIXTURE_INTENTIONAL_CRASH";

export async function startWebServer(configuration = process.env) {
  if (configuration.QA_STARTUP_MODE === "crash") {
    process.stderr.write(`${CRASH_MARKER}\n`);
    process.exitCode = 42;
    return null;
  }

  const port = parsePort(configuration.PORT);
  const app = await createWebApp(configuration);
  const server = app.listen(port, "0.0.0.0");
  const stop = () => server.close(async () => {
    try {
      await app.locals.closeResources();
    } finally {
      process.exit(0);
    }
  });
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  return server;
}

function parsePort(value) {
  if (value === undefined || value === "") return 3000;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("PORT must be an integer between 0 and 65535.");
  }
  return port;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  await startWebServer();
}
