import { Router, type IRouter } from "express";
import { requireAuth, requireSubmenuAccess } from "../lib/auth";
import { tenantContextMiddleware } from "../lib/tenant";
import adminRouter from "./admin";
import agentRouter from "./agent";
import authRouter from "./auth";
import checkinsRouter from "./checkins";
import filesRouter from "./files";
import healthRouter from "./health";
import labRouter from "./lab";
import loginRouter from "./login";
import peripheralsRouter from "./peripherals";
import registerRouter from "./register";
import reportsRouter from "./reports";
import securityRouter from "./security";
import settingsRouter from "./settings";
import usbDevicesRouter from "./usb-devices";

// ---------------------------------------------------------------------------
// Platform API (mounted at /api)
// ---------------------------------------------------------------------------
// Reached without a tenant prefix: health, public tenant registration, and
// the platform admin endpoints (login is public, everything under /admin is
// gated by requirePlatformAuth inside adminRouter).
// ---------------------------------------------------------------------------

const router: IRouter = Router();

router.use(healthRouter);
router.use(registerRouter);
router.use(loginRouter);
router.use(adminRouter);

// ---------------------------------------------------------------------------
// Tenant API (mounted at /t/:slug/api)
// ---------------------------------------------------------------------------
// A tenant's whole surface — agents, dashboard auth, and lab APIs — lives
// under its own schema, resolved from the slug in the URL.
// ---------------------------------------------------------------------------

const tenantRouter: IRouter = Router();

tenantRouter.use(tenantContextMiddleware);

// Reachable without a dashboard session (agents authenticate via their token,
// the auth router manages its own login flow).
tenantRouter.use(authRouter);
tenantRouter.use(agentRouter);

// Everything after this point requires a valid tenant dashboard session.
// Admins are further limited to the APIs of the submenus granted in
// `submenu_access`.
tenantRouter.use(requireAuth);
tenantRouter.use(requireSubmenuAccess);

tenantRouter.use(checkinsRouter);
tenantRouter.use(filesRouter);
tenantRouter.use(labRouter);
tenantRouter.use(peripheralsRouter);
tenantRouter.use(reportsRouter);
tenantRouter.use(securityRouter);
tenantRouter.use(settingsRouter);
tenantRouter.use(usbDevicesRouter);

export default router;
export { tenantRouter };
