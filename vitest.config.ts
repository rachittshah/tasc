import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts"],
      reporter: ["text", "json-summary", "lcov"],
      reportsDirectory: "coverage",
      clean: true,
      // Floor measured on the complete 788-test suite on 2026-07-29:
      // 85.64% statements, 80.04% branches, 96.98% functions, 87.14% lines.
      // Integer floors preserve a small runtime/instrumentation margin while
      // preventing unreviewed coverage regression across all production src.
      thresholds: {
        statements: 85,
        branches: 79,
        functions: 96,
        lines: 87,
      },
    },
  },
});
