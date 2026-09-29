import express, { type Express } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import rateLimit from "express-rate-limit";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import router, { tenantRouter } from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();

// Trust the first proxy hop so req.ip reflects the real client when deployed
// behind Render's edge (and any CDN in front of it). Without this, every
// request looks like it comes from the proxy and per-IP limits are useless.
app.set("trust proxy", 1);

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          // Query strings are dropped: they carry agent tokens on some routes
          // and session material on others, and this log ships off-box.
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);

// --- CORS ------------------------------------------------------------------
// Default to same-origin only. A browser sends `Origin` on cross-origin
// requests, so an unset allowlist means only requests without an Origin header
// (same-origin navigations, curl, the agent) are permitted. Set
// ALLOWED_ORIGINS to a comma-separated list to permit additional origins.
const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.length === 0) {
        callback(null, true);
        return;
      }
      callback(null, allowedOrigins.includes(origin));
    },
    credentials: true,
  }),
);

app.use(cookieParser());

// Explicit body limits. body-parser's 100kb default is inherited otherwise,
// which is fine but unintentional — and screenshots/file pushes are the
// legitimate large payloads, so keep JSON modest and allow the body parser a
// clear ceiling rather than an accidental one.
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// --- Rate limiting ---------------------------------------------------------
// Split by surface: a single global limit would be wrong in both directions.
// Login endpoints are the brute-force target and get a tight budget. Agent
// traffic is high-frequency (a 10s heartbeat per PC) and is already
// token-authenticated, so it gets a generous ceiling. Everything else gets a
// moderate default that still stops runaway scripts.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again later." },
});

const agentLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 600,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Agent rate limit exceeded" },
});

const defaultLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many requests" },
});

// Two distinct login surfaces: the platform owner's /api/login, and the tenant
// dashboard's /api/auth/login (mounted at both /api and /t/:slug/api).
app.use("/api/login", authLimiter);
app.use("/api/auth/login", authLimiter);
app.use("/t/:slug/api/auth/login", authLimiter);
app.use("/t/:slug/api/login", authLimiter);
app.use("/api/agent", agentLimiter);
app.use("/t/:slug/api/agent", agentLimiter);
app.use("/api", defaultLimiter);
app.use("/t/:slug/api", defaultLimiter);

// Serve the built frontend (artifacts/lab-control/dist/public) when present.
// The bundle lives in artifacts/api-server/dist, so `../../lab-control/...`
// resolves to artifacts/lab-control/...
const frontendDir = fileURLToPath(
  new URL("../../lab-control/dist/public", import.meta.url),
);
app.use(express.static(frontendDir));

app.use("/api", router);
app.use("/t/:slug/api", tenantRouter);

// SPA fallback: hand every non-API GET request to the frontend.
app.use((req, res, next) => {
  if (req.method !== "GET") {
    next();
    return;
  }
  const pathname = req.path;
  if (pathname.startsWith("/api") || /^\/t\/[^/]+\/api(\/|$)/.test(pathname)) {
    next();
    return;
  }

  const indexPath = path.join(frontendDir, "index.html");
  if (existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.json({
      message:
        "LVO Security API is running. The dashboard has not been built yet.",
    });
  }
});

export default app;
