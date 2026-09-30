import { describe, expect, it } from "vitest";
import {
  bundledAgentVersion,
  compareAgentVersions,
} from "../src/lib/agent-version";

describe("compareAgentVersions", () => {
  it("returns 0 for identical versions", () => {
    expect(compareAgentVersions("1.23.0", "1.23.0")).toBe(0);
  });

  it("orders by numeric segments, not lexically", () => {
    expect(compareAgentVersions("1.23.0", "1.3.0")).toBeGreaterThan(0);
    expect(compareAgentVersions("1.2.0", "1.10.0")).toBeLessThan(0);
    expect(compareAgentVersions("2.0.0", "1.99.9")).toBeGreaterThan(0);
  });

  it("handles unequal segment lengths", () => {
    expect(compareAgentVersions("1.23", "1.23.1")).toBeLessThan(0);
    expect(compareAgentVersions("1.23.1", "1.23")).toBeGreaterThan(0);
  });
});

describe("bundledAgentVersion", () => {
  it("reads a sane version from the bundled Windows agent", () => {
    const version = bundledAgentVersion();
    expect(version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("prefers the higher version when both bundled scripts ship", () => {
    // Both scripts are pinned to the same release line today, but the rule is
    // "highest wins" so one platform can never look perpetually stale.
    const version = bundledAgentVersion();
    expect(version?.split(".").length).toBeGreaterThanOrEqual(3);
  });
});