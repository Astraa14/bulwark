import test from "node:test";
import assert from "node:assert/strict";

import { findingIdentity } from "./finding-identity.mjs";

test("finding identity distinguishes separate affected resources", () => {
  assert.notEqual(
    findingIdentity({ check_key: "exposed_env", url: "https://example.com/.env" }),
    findingIdentity({ check_key: "exposed_env", url: "https://example.com/api/.env" }),
  );
});

test("finding identity ignores query strings and fragments", () => {
  assert.equal(
    findingIdentity({ check_key: "secret", url: "https://example.com/app.js?token=one#part" }),
    findingIdentity({ check_key: "secret", url: "https://example.com/app.js?token=two" }),
  );
});

test("finding identity includes the check key", () => {
  assert.notEqual(
    findingIdentity({ check_key: "header_csp", url: "https://example.com/" }),
    findingIdentity({ check_key: "header_hsts", url: "https://example.com/" }),
  );
});
