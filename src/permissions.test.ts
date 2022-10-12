import assert from "node:assert";
import test, { describe, it } from "node:test";
import { AccessControl, Role } from "./permissions";

describe("serialization", () => {
  describe("when empty", () => {
    it("returns empty object", () => {
      const role = new Role({});
      assert.strictEqual(role.toString(), "{}");
    });
  });
  describe("with resources", () => {
    it("serializes correctly", () => {
      const role = new Role({
        "r1": ["a", "b"],
      });
      assert.strictEqual(role.toString(), '{"r1":["a","b"]}');
    });
  });
});

describe("deserialization", () => {
  describe("when empty", () => {
    it("creates role", () => {
      const role = Role.fromString("{}");
      assert.deepEqual(role.statements, {});
    });
  });
  describe("with resources", () => {
    it("serializes correctly", () => {
      const role = Role.fromString('{"r1":["a","b"]}');
      assert.deepEqual(role.statements, { r1: ["a", "b"] });
    });
  });
});

describe("allow", () => {
  describe("without access", () => {
    it("denies the request", () => {
      const ac = new AccessControl<{ r: ["r", "w"] }>();
      const role = ac.newRole({ r: ["r"] });
      const { success, error } = role.allow("r", ["r", "w"]);
      assert.equal(success, false);
      assert.equal(error, 'not authorized for action "w" on resource: "r"');
    });
  });
  describe("with access", () => {
    it("serializes correctly", () => {
      const ac = new AccessControl<{ r: ["r", "w"] }>();
      const role = ac.newRole({ r: ["r"] });
      const { success, error } = role.allow("r", ["r"]);
      assert.equal(success, true);
      assert.equal(error, undefined);
    });
  });
});
