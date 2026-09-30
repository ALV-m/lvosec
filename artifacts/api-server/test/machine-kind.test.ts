import { describe, expect, it } from "vitest";
import { classifyMachineKind } from "../src/lib/machine-kind";

describe("classifyMachineKind", () => {
  it("maps Windows and unspecified OS to computer", () => {
    expect(classifyMachineKind("Windows 11 Pro")).toBe("computer");
    expect(classifyMachineKind("Windows 10 Pro")).toBe("computer");
    expect(classifyMachineKind(null)).toBe("computer");
    expect(classifyMachineKind(undefined)).toBe("computer");
  });

  it("maps Ubuntu/Debian VPS labels to vps", () => {
    expect(classifyMachineKind("Ubuntu 24.04.1 LTS (6.8.0-45-generic)")).toBe("vps");
    expect(classifyMachineKind("Debian GNU/Linux 12 (bookworm)")).toBe("vps");
    expect(classifyMachineKind("Ubuntu 22.04.4 LTS")).toBe("vps");
  });

  it("maps other common server distributions to vps", () => {
    expect(classifyMachineKind("CentOS Stream 9")).toBe("vps");
    expect(classifyMachineKind("Red Hat Enterprise Linux 9")).toBe("vps");
    expect(classifyMachineKind("AlmaLinux 9.4")).toBe("vps");
    expect(classifyMachineKind("Fedora Linux 40")).toBe("vps");
  });

  it("maps a bare 'Linux' label to vps", () => {
    expect(classifyMachineKind("Linux")).toBe("vps");
  });
});