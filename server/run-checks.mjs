// Quick manual check: node server/run-checks.mjs example.com
import { runChecks } from "./checks.mjs";

const domain = process.argv[2];
if (!domain) {
  console.error("Usage: node server/run-checks.mjs <domain>");
  process.exit(1);
}

const result = await runChecks(domain);
console.log(JSON.stringify(result, null, 2));
