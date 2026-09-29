import { boolean, pgTable, serial, text, timestamp } from "drizzle-orm/pg-core";

// Platform-level (public schema) table backing the Super Admin "DB Management"
// dashboard: a registry of Postgres connection URLs the platform admin manages
// under one view. One row may be marked `is_active` — the database the admin
// has chosen as the current one for their sites to use.
export const platformDbConnectionsTable = pgTable("platform_db_connections", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  url: text("url").notNull(),
  note: text("note"),
  isActive: boolean("is_active").notNull().default(false),
  status: text("status").notNull().default("unknown"),
  lastCheckedAt: timestamp("last_checked_at", { withTimezone: true }),
  lastError: text("last_error"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});