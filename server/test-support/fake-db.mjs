import { randomUUID } from "node:crypto";

const UNIQUE_KEYS = {
  platform_scan_jobs: [["connection_id", "delivery_id"]],
  scans: [["connection_id", "delivery_id"]],
};

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function matchesFilter(row, filter) {
  const value = row[filter.column];
  switch (filter.op) {
    case "eq":
      return value === filter.value;
    case "is":
      return (value ?? null) === filter.value;
    case "not":
      return filter.operator === "is" && filter.value === null
        ? value !== null && value !== undefined
        : value !== filter.value;
    case "gte":
      return value !== null && value !== undefined && String(value) >= String(filter.value);
    case "lte":
      return value !== null && value !== undefined && String(value) <= String(filter.value);
    case "in":
      return Array.isArray(filter.value) && filter.value.includes(value);
    default:
      return true;
  }
}

class FakeQuery {
  constructor(db, table) {
    this.db = db;
    this.table = table;
    this.op = "select";
    this.payload = null;
    this.columns = "*";
    this.filters = [];
    this.orderBy = null;
    this.limitCount = null;
    this.singleMode = null;
  }

  select(columns = "*") {
    this.columns = columns;
    return this;
  }

  eq(column, value) {
    this.filters.push({ op: "eq", column, value });
    return this;
  }

  is(column, value) {
    this.filters.push({ op: "is", column, value });
    return this;
  }

  not(column, operator, value) {
    this.filters.push({ op: "not", column, operator, value });
    return this;
  }

  gte(column, value) {
    this.filters.push({ op: "gte", column, value });
    return this;
  }

  lte(column, value) {
    this.filters.push({ op: "lte", column, value });
    return this;
  }

  in(column, value) {
    this.filters.push({ op: "in", column, value });
    return this;
  }

  order(column, { ascending = true } = {}) {
    this.orderBy = { column, ascending };
    return this;
  }

  limit(count) {
    this.limitCount = count;
    return this;
  }

  insert(payload) {
    this.op = "insert";
    this.payload = payload;
    return this;
  }

  update(payload) {
    this.op = "update";
    this.payload = payload;
    return this;
  }

  delete() {
    this.op = "delete";
    return this;
  }

  upsert(payload, options = {}) {
    this.op = "upsert";
    this.payload = payload;
    this.onConflict = options.onConflict;
    return this;
  }

  maybeSingle() {
    this.singleMode = "maybe";
    return this;
  }

  single() {
    this.singleMode = "single";
    return this;
  }

  rows() {
    if (!this.db.tables.has(this.table)) this.db.tables.set(this.table, []);
    return this.db.tables.get(this.table);
  }

  matching(rows) {
    return rows.filter((row) => this.filters.every((filter) => matchesFilter(row, filter)));
  }

  uniqueViolation(row) {
    const keys = UNIQUE_KEYS[this.table] ?? [];
    for (const key of keys) {
      if (key.some((column) => row[column] === null || row[column] === undefined)) continue;
      const exists = this.rows().some((existing) =>
        key.every((column) => existing[column] === row[column]),
      );
      if (exists) return { code: "23505", message: "duplicate key value violates unique constraint" };
    }
    return null;
  }

  exec() {
    let rows = this.rows();
    this.db.calls.push({
      table: this.table,
      op: this.op,
      filters: clone(this.filters),
      payload: clone(this.payload),
    });

    if (this.op === "insert" || this.op === "upsert") {
      const values = Array.isArray(this.payload) ? this.payload : [this.payload];
      const inserted = [];
      for (const value of values) {
        const row = { id: randomUUID(), created_at: new Date().toISOString(), ...value };

        if (this.op === "insert") {
          const violation = this.uniqueViolation(row);
          if (violation) return { data: null, error: violation };
        } else {
          const conflictColumns = String(this.onConflict ?? "id").split(",");
          const index = rows.findIndex((existing) =>
            conflictColumns.every((column) => existing[column] === row[column]),
          );
          if (index >= 0) {
            rows[index] = { ...rows[index], ...row };
            inserted.push(rows[index]);
            continue;
          }
        }

        rows.push(row);
        inserted.push(row);
      }
      this.db.tables.set(this.table, rows);
      return this.shape(inserted);
    }

    if (this.op === "update") {
      const targets = this.matching(rows);
      for (const row of targets) Object.assign(row, this.payload);
      return this.shape(targets);
    }

    if (this.op === "delete") {
      const remaining = rows.filter((row) => !this.matching([row]).length);
      this.db.tables.set(this.table, remaining);
      return { data: null, error: null };
    }

    let selected = this.matching(rows);
    if (this.orderBy) {
      const { column, ascending } = this.orderBy;
      selected = selected.slice().sort((a, b) => {
        const left = a[column] ?? "";
        const right = b[column] ?? "";
        if (left === right) return 0;
        return (left < right ? -1 : 1) * (ascending ? 1 : -1);
      });
    }
    if (this.limitCount !== null) selected = selected.slice(0, this.limitCount);

    if (this.table === "findings" && String(this.columns).includes("sites")) {
      const sites = this.db.tables.get("sites") ?? [];
      selected = selected.map((row) => ({
        ...row,
        sites: sites.find((site) => site.id === row.site_id) ?? null,
      }));
    }

    return this.shape(selected);
  }

  shape(rows) {
    const data = rows.map(clone);
    if (this.singleMode === "single") {
      if (data.length !== 1) {
        return {
          data: null,
          error: { code: "PGRST116", message: `expected one row, got ${data.length}` },
        };
      }
      return { data: data[0], error: null };
    }
    if (this.singleMode === "maybe") return { data: data[0] ?? null, error: null };
    return { data, error: null };
  }

  then(resolve, reject) {
    try {
      resolve(this.exec());
    } catch (error) {
      reject(error);
    }
  }
}

/**
 * A tiny in-memory stand-in for the Supabase JS client. It implements only the
 * query shapes Bulwark uses, including the unique constraints that matter for
 * webhook idempotency.
 */
export function createFakeDb({
  tables = {},
  users = {
    "token-a": { id: "user-a", email: "a@example.com" },
    "token-b": { id: "user-b", email: "b@example.com" },
  },
  rpcHandlers = {},
} = {}) {
  const db = {
    tables: new Map(Object.entries(tables).map(([name, rows]) => [name, rows.map(clone)])),
    calls: [],
    rpcCalls: [],
    auth: {
      async getUser(jwt) {
        const user = users[jwt];
        return user
          ? { data: { user }, error: null }
          : { data: { user: null }, error: { message: "invalid token" } };
      },
    },
    from(table) {
      if (!db.tables.has(table)) db.tables.set(table, []);
      return new FakeQuery(db, table);
    },
    async rpc(name, args = {}) {
      db.rpcCalls.push({ name, args: clone(args) });
      const handler = rpcHandlers[name];
      if (handler) return handler(args, db);
      if (name === "persist_platform_scan_result") {
        const scans = db.tables.get("scans") ?? [];
        const existing = scans.find(
          (scan) =>
            scan.id === args.p_scan_id ||
            (args.p_delivery_id &&
              scan.connection_id === args.p_connection_id &&
              scan.delivery_id === args.p_delivery_id),
        );
        if (existing && ["completed", "partial"].includes(existing.status)) {
          return {
            data: {
              scanId: existing.id,
              duplicate: true,
              newFindings: [],
              reopenedFindings: [],
            },
            error: null,
          };
        }
        if (!existing) {
          scans.push({
            id: args.p_scan_id,
            user_id: args.p_user_id,
            platform: args.p_platform,
            connection_id: args.p_connection_id,
            resource: args.p_resource,
            status: args.p_status,
            delivery_id: args.p_delivery_id,
            started_at: args.p_started_at,
            finished_at: args.p_finished_at,
          });
          db.tables.set("scans", scans);
        }
        return {
          data: {
            scanId: args.p_scan_id,
            duplicate: false,
            newFindings: (args.p_findings ?? []).map((finding) => ({
              id: randomUUID(),
              check_key: finding.check_key,
              title: finding.title,
              severity: finding.severity,
              detail: finding.detail,
              url: finding.url,
            })),
            reopenedFindings: [],
          },
          error: null,
        };
      }
      if (name === "claim_platform_scan_jobs") return { data: [], error: null };
      if (name === "enqueue_due_supabase_scans") return { data: [], error: null };
      if (name === "claim_site_scan") return { data: true, error: null };
      if (name === "release_site_scan") return { data: null, error: null };
      return { data: null, error: null };
    },
  };

  return db;
}
