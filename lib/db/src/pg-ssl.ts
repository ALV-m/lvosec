// ---------------------------------------------------------------------------
// Postgres TLS resolution
// ---------------------------------------------------------------------------
// Managed Postgres in production (Render, Neon, Supabase, …) typically
// requires SSL/TLS for (external) connections, while a local dev database is
// plaintext. A bare `postgres://` URL carries no signal, so we resolve:
//
//   1. an explicit `sslmode` query parameter wins when present;
//   2. otherwise, production defaults to TLS (with the standard
//      rejectUnauthorized:false used by `sslmode=require`), so a Render
//      "Internal Database URL" — which has no sslmode param but still enforces
//      TLS — connects without editing the URL;
//   3. anything not in production stays plaintext so `docker compose`
//      / local Postgres keeps working untouched.
// ---------------------------------------------------------------------------

export interface PgSslDecision {
  ssl: boolean | { rejectUnauthorized: boolean };
}

function parseQuery(url: string): URLSearchParams {
  try {
    return new URL(url).searchParams;
  } catch {
    return new URLSearchParams();
  }
}

export function resolvePgSsl(
  databaseUrl: string,
  isProduction: boolean,
): PgSslDecision {
  const sslmode = parseQuery(databaseUrl).get("sslmode");
  if (sslmode) {
    switch (sslmode) {
      case "disable":
        return { ssl: false };
      case "verify-full":
      case "verify-ca":
        return { ssl: { rejectUnauthorized: true } };
      case "allow":
      case "prefer":
      case "require":
      case "no-verify":
      default:
        return { ssl: { rejectUnauthorized: false } };
    }
  }
  if (isProduction) {
    return { ssl: { rejectUnauthorized: false } };
  }
  return { ssl: false };
}