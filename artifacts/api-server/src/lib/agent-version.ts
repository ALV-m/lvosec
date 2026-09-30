import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Bundled agent versions, shared by the heartbeat (so agents know when a newer
 * script exists) and the Blue Team posture engine (so "agent up to date" is
 * truthful for both the Windows PowerShell agent and the Linux agent).
 *
 * Both scripts are copied next to the bundle at build time
 * (artifacts/api-server/build.mjs). Which one wins the "latest" crown is
 * decided by a simple dotted-version comparison, so a release can land on
 * both platforms at the same version number and neither is "stale".
 */

interface AgentScriptDef {
  fileName: string;
  versionPattern: RegExp;
}

const AGENT_SCRIPTS: AgentScriptDef[] = [
  {
    fileName: "lab-agent.ps1",
    versionPattern: /\$script:AgentVersion\s*=\s*'([^']+)'/,
  },
  {
    fileName: "lab-agent-linux.py",
    versionPattern: /LVOSEC_AGENT_VERSION\s*=\s*['"]([^'"]+)['"]/,
  },
];

// dist/ — both scripts sit next to the single bundled server file. When
// running from source (tsx / vitest) fall back to src/assets.
const DIST_DIR = path.dirname(fileURLToPath(import.meta.url));
const SRC_ASSETS_DIR = path.join(DIST_DIR, "..", "assets");

function readScriptVersion(def: AgentScriptDef): string | null {
  const locations = [
    path.join(DIST_DIR, def.fileName),
    path.join(SRC_ASSETS_DIR, def.fileName),
  ];
  for (const location of locations) {
    try {
      const source = readFileSync(location, "utf8");
      const match = source.match(def.versionPattern);
      const version = match?.[1];
      if (version) return version;
    } catch {
      // Try the next location.
    }
  }
  return null;
}

/** Compare dotted versions like "1.23.0", fall back to string compare. */
export function compareAgentVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => Number.parseInt(n, 10));
  const pb = b.split(".").map((n) => Number.parseInt(n, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = Number.isFinite(pa[i]) ? pa[i] : 0;
    const nb = Number.isFinite(pb[i]) ? pb[i] : 0;
    if (na !== nb) return na > nb ? 1 : -1;
  }
  return a === b ? 0 : a > b ? 1 : -1;
}

/** Highest agent version advertised by any bundled script, or null. */
export function bundledAgentVersion(): string | null {
  let best: string | null = null;
  for (const def of AGENT_SCRIPTS) {
    const version = readScriptVersion(def);
    if (version && (best === null || compareAgentVersions(version, best) > 0)) {
      best = version;
    }
  }
  return best;
}