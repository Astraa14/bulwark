import test from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDir = path.join(root, "supabase", "migrations");
const applyAllPath = path.join(root, "supabase", "apply_all.sql");

const migrationFiles = (await readdir(migrationsDir))
  .filter((name) => name.endsWith(".sql"))
  .sort();

test("apply_all.sql contains every migration verbatim and in order", async () => {
  const applyAll = await readFile(applyAllPath, "utf8");

  let cursor = -1;
  for (const file of migrationFiles) {
    const sql = (await readFile(path.join(migrationsDir, file), "utf8")).trimEnd();
    const marker = `-- >>> supabase/migrations/${file}`;
    const index = applyAll.indexOf(marker);
    assert.ok(index >= 0, `apply_all.sql is missing ${file}; run npm run db:apply-all`);
    assert.ok(index > cursor, `apply_all.sql has ${file} out of order`);
    assert.ok(
      applyAll.includes(sql),
      `apply_all.sql does not contain the current contents of ${file}; run npm run db:apply-all`,
    );
    cursor = index;
  }
});

test("ownership migration enables RLS and scopes findings to auth.uid()", async () => {
  const ownership = await readFile(
    path.join(migrationsDir, "20261115000000_platform_ownership.sql"),
    "utf8",
  );

  assert.match(ownership, /add column if not exists user_id uuid/i);
  assert.match(ownership, /alter table public\.findings enable row level security/i);
  assert.match(ownership, /alter table public\.scans enable row level security/i);
  assert.match(
    ownership,
    /create policy "findings_select_own"[\s\S]*?using \(auth\.uid\(\) = user_id\)/i,
  );
  assert.match(
    ownership,
    /create policy "findings_update_own"[\s\S]*?with check \(auth\.uid\(\) = user_id\)/i,
  );
  assert.doesNotMatch(
    ownership,
    /create policy "findings_select_own"[\s\S]{0,200}using \(true\)/i,
    "findings RLS must not allow all rows",
  );
  assert.doesNotMatch(
    ownership,
    /add constraint findings_owner_shape/i,
    "a hard owner check would break the previously deployed code during the migration window",
  );
  assert.match(ownership, /unique \(connection_id, owner, name\)/i);
  assert.match(
    ownership,
    /create unique index if not exists platform_scan_jobs_delivery_idx[\s\S]*?\(connection_id, delivery_id\)/i,
  );
});

test("platform scan RPC is owner/connection/resource scoped and retry safe", async () => {
  const atomic = await readFile(
    path.join(migrationsDir, "20261115010000_atomic_platform_scan.sql"),
    "utf8",
  );

  assert.match(atomic, /create or replace function public\.persist_platform_scan_result/i);
  assert.match(atomic, /p_delivery_id text default null/i);
  assert.match(atomic, /'duplicate', true/i);
  assert.match(atomic, /and connection_id = p_connection_id/i);
  assert.match(atomic, /and resource = p_resource/i);
  assert.match(atomic, /idempotency_key = p_idempotency_key/i);
  assert.match(
    atomic,
    /create or replace function public\.persist_scan_result\(\s*p_scan_id uuid,\s*p_site_id uuid,/i,
    "the 19-argument compatibility wrapper must exist for the deployed worker",
  );
  assert.match(atomic, /create or replace function public\.claim_platform_scan_jobs/i);
  assert.match(atomic, /for update skip locked/i);
  assert.match(atomic, /attempts < 5/i);
});

test("the customer RLS helper is not installed in Bulwark's own database", async () => {
  const removal = await readFile(
    path.join(migrationsDir, "20261115020000_remove_app_rls_helper.sql"),
    "utf8",
  );
  const customer = await readFile(
    path.join(root, "supabase", "customer", "bulwark_check_rls.sql"),
    "utf8",
  );

  assert.match(removal, /drop function if exists public\.bulwark_check_rls/i);
  assert.match(customer, /n\.nspname = 'public'/i);
  assert.match(customer, /has_permissive_policy/i);
  assert.match(customer, /heuristic/i);
  assert.doesNotMatch(customer, /select \* from/i, "the helper must not read table contents");
});

test("RLS is owner-only and never exposes null-owner or foreign rows", async () => {
  const ownership = await readFile(
    path.join(migrationsDir, "20261115000000_platform_ownership.sql"),
    "utf8",
  );

  assert.match(
    ownership,
    /create policy "findings_select_own"[\s\S]*?for select using \(auth\.uid\(\) = user_id\)/i,
  );
  assert.match(
    ownership,
    /create policy "findings_update_own"[\s\S]*?for update using \(auth\.uid\(\) = user_id\)[\s\S]*?with check \(auth\.uid\(\) = user_id\)/i,
  );
  assert.match(
    ownership,
    /create policy "scans_select_own"[\s\S]*?for select using \(auth\.uid\(\) = user_id\)/i,
  );
  assert.doesNotMatch(
    ownership,
    /create policy "[^"]+"[\s\S]{0,300}?using \(true\)/i,
    "no policy may allow every row",
  );
  assert.doesNotMatch(
    ownership,
    /create policy "findings_(insert|delete)[^"]*"/i,
    "browser clients must not insert or delete findings",
  );
  assert.doesNotMatch(
    ownership,
    /create policy "scans_(insert|update|delete)[^"]*"/i,
    "browser clients must not write scans",
  );
  assert.match(
    ownership,
    /create policy "github_repositories_select_own"[\s\S]*?using \(auth\.uid\(\) = user_id\)/i,
  );
  assert.match(ownership, /alter table public\.platform_scan_jobs enable row level security/i);
});

test("the ownership backfill never guesses an owner for platform rows", async () => {
  const ownership = await readFile(
    path.join(migrationsDir, "20261115000000_platform_ownership.sql"),
    "utf8",
  );

  assert.match(ownership, /update public\.findings f[\s\S]*?set user_id = s\.user_id/i);
  assert.match(ownership, /where f\.site_id = s\.id[\s\S]*?and f\.user_id is null/i);
  assert.doesNotMatch(
    ownership,
    /update public\.findings[\s\S]{0,400}?set user_id = [^;]*?where user_id is null\s*;/i,
    "unowned platform rows must stay unowned",
  );
});
