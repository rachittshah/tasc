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
      // Initial floor measured on the complete 657-test suite on 2026-07-28:
      // 85.79% statements, 79.91% branches, 96.62% functions, 87.44% lines.
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
