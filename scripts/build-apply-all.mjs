import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDir = path.join(root, "supabase", "migrations");
const target = path.join(root, "supabase", "apply_all.sql");
const checkOnly = process.argv.includes("--check");

const files = (await readdir(migrationsDir))
  .filter((name) => name.endsWith(".sql"))
  .sort();

if (files.length === 0) throw new Error("No migrations found.");

const parts = [
  "-- ===========================================================================",
  "-- Bulwark: run this once in Supabase -> SQL Editor -> New query.",
  "-- Combines every migration in order. Statements are idempotent, so it is",
  "-- safe to re-run this file after updating the app.",
  "--",
  "-- This file is generated. Edit supabase/migrations/*.sql instead, then run",
  "-- `npm run db:apply-all`.",
  "--",
  "-- The RLS introspection helper for customer projects is NOT part of this",
  "-- file. It lives at supabase/customer/bulwark_check_rls.sql.",
  "-- ===========================================================================",
  "",
];

const normalizeEol = (value) => value.replace(/\r\n/g, "\n");

for (const name of files) {
  const sql = normalizeEol(await readFile(path.join(migrationsDir, name), "utf8"));
  parts.push(`-- >>> supabase/migrations/${name}`);
  parts.push(sql.trimEnd());
  parts.push("");
}

const output = `${parts.join("\n").trimEnd()}\n`;

if (checkOnly) {
  let current = "";
  try {
    current = normalizeEol(await readFile(target, "utf8"));
  } catch {
    current = "";
  }
  if (current !== output) {
    console.error(
      "supabase/apply_all.sql is out of date. Run `npm run db:apply-all` and commit the result.",
    );
    process.exit(1);
  }
  console.log(`supabase/apply_all.sql is current (${files.length} migration(s)).`);
} else {
  await writeFile(target, output, "utf8");
  console.log(`Wrote ${path.relative(root, target)} from ${files.length} migration(s).`);
}
