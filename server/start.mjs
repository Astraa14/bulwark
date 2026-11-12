import { spawn } from "node:child_process";

// Runs the API and the scan worker together in one container.
// If either process dies the other is stopped, so Render restarts the service
// instead of silently running without scans (or without an API).

const children = [
  spawn(process.execPath, ["server/api.mjs"], { stdio: "inherit" }),
  spawn(process.execPath, ["server/worker.mjs"], { stdio: "inherit" }),
];

let stopping = false;

function shutdown(code) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  setTimeout(() => process.exit(code), 2500).unref();
}

for (const child of children) {
  child.on("exit", (code) => shutdown(code ?? 0));
  child.on("error", (err) => {
    console.error(err);
    shutdown(1);
  });
}

process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));
