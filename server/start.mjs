import { spawn } from "node:child_process";

// Runs the API and the scan worker together in one container.
// If either process dies the other is stopped, so Render restarts the service
// instead of silently running without scans (or without an API).

console.log(
  "Bulwark starting · Application-level SSRF protection enforced · " +
    "Consider network-level egress controls (firewall/VPC) to block outbound " +
    "traffic to private IP ranges (see render.yaml).",
);

const children = [
  spawn(process.execPath, ["server/api.mjs"], { stdio: "inherit" }),
  spawn(process.execPath, ["server/worker.mjs"], { stdio: "inherit" }),
];

let stopping = false;
let exitCode = 0;
let alive = children.length;

function shutdown(code) {
  if (!stopping) {
    stopping = true;
    exitCode = code;
    for (const child of children) {
      if (child.exitCode === null) child.kill("SIGTERM");
    }
    setTimeout(() => process.exit(exitCode), 11_000).unref();
  }
  if (alive <= 0) process.exit(exitCode);
}

for (const child of children) {
  child.on("exit", (code) => {
    alive -= 1;
    shutdown(stopping ? exitCode : (code ?? 0));
  });
  child.on("error", (err) => {
    console.error(err);
    shutdown(1);
  });
}

process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));
