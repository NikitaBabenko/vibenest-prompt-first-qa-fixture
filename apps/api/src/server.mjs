import { pathToFileURL } from "node:url";
import { createApiApp } from "./app.mjs";

export function startApiServer(configuration = process.env) {
  const port = parsePort(configuration.PORT);
  const app = createApiApp(configuration);
  const server = app.listen(port, "0.0.0.0");

  const stop = () => {
    server.close(async () => {
      await app.locals.closeResources();
      process.exit(0);
    });
  };
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
  startApiServer();
}
