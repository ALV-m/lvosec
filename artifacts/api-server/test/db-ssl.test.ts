import { describe, expect, it } from "vitest";
import { resolvePgSsl } from "../../../lib/db/src/pg-ssl";

describe("resolvePgSsl", () => {
  it("honors sslmode=require from the URL", () => {
    expect(
      resolvePgSsl("postgres://u:p@host/db?sslmode=require", false).ssl,
    ).toEqual({ rejectUnauthorized: false });
  });

  it("honors sslmode=verify-full from the URL", () => {
    expect(
      resolvePgSsl("postgres://u:p@host/db?sslmode=verify-full", false).ssl,
    ).toEqual({ rejectUnauthorized: true });
  });

  it("honors sslmode=disable from the URL", () => {
    expect(
      resolvePgSsl("postgres://u:p@host/db?sslmode=disable", true).ssl,
    ).toBe(false);
  });

  it("keeps an already-parameterised URL's other params intact", () => {
    expect(
      resolvePgSsl("postgres://u:p@host/db?pgbouncer=true&sslmode=require", false)
        .ssl,
    ).toEqual({ rejectUnauthorized: false });
  });

  it("defaults to TLS in production when the URL has no sslmode", () => {
    expect(
      resolvePgSsl("postgres://u:p@dpg-abcdef-a/dbname", true).ssl,
    ).toEqual({ rejectUnauthorized: false });
  });

  it("stays plaintext outside production when the URL has no sslmode", () => {
    expect(
      resolvePgSsl("postgres://u:p@localhost:5432/db", false).ssl,
    ).toBe(false);
  });

  it("does not crash on an unparseable URL", () => {
    expect(() => resolvePgSsl("not a url", true)).not.toThrow();
  });
});