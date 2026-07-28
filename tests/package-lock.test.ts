import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

interface LockPackage {
  optionalDependencies?: Record<string, string>;
}

interface PackageLock {
  packages: Record<string, LockPackage>;
}

describe("cross-platform package lock", () => {
  it("locks every rolldown native binding declared by the test toolchain", async () => {
    const lock = JSON.parse(
      await readFile(new URL("../package-lock.json", import.meta.url), "utf8"),
    ) as PackageLock;
    const rolldown = lock.packages["node_modules/rolldown"];

    expect(rolldown?.optionalDependencies).toBeDefined();
    for (const dependency of Object.keys(rolldown?.optionalDependencies ?? {})) {
      expect(
        lock.packages[`node_modules/${dependency}`],
        `${dependency} is absent; regenerate package-lock.json without node_modules`,
      ).toBeDefined();
    }

    expect(lock.packages["node_modules/@rolldown/binding-darwin-arm64"]).toBeDefined();
    expect(lock.packages["node_modules/@rolldown/binding-darwin-x64"]).toBeDefined();
  });
});
