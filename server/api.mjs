import { startApi } from "./app.mjs";

const server = startApi();

let stopping = false;
function shutdown() {
  if (stopping) return;
  stopping = true;
  const force = setTimeout(() => process.exit(0), 10_000);
  force.unref();
  server.close(() => process.exit(0));
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
