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
        "r1": [{ action: "a" }, { action: "b" }],
      });
      assert.strictEqual(
        role.toString(),
        '{"r1":[{"action":"a"},{"action":"b"}]}',
      );
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

describe("authorize", () => {
  describe("without access", () => {
    it("denies the request", () => {
      const ac = new AccessControl<{
        res1: [{ action: "r" }, { action: "w" }];
      }>();
      const role = ac.newRole({ res1: [{ action: "r" }] });
      const { success, error } = role.authorize({
        "res1": [{ action: "r" }, { action: "w" }],
      });
      assert.equal(success, false);
      assert.equal(error, 'unauthorized to access resource "res1"');
    });
  });
  describe("with access", () => {
    it("allows the request", () => {
      const ac = new AccessControl<{ r: [{ action: "r" }, { action: "w" }] }>();
      const role = ac.newRole({ r: [{ action: "r" }] });
      const { success, error } = role.authorize({ "r": [{ action: "r" }] });
      assert.equal(success, true);
      assert.equal(error, undefined);
    });
  });
});
