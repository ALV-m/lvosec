// ---------------------------------------------------------------------------
// Machine kind — Platforms are protected as two *different services* in the
// Platform Admin dashboard:
//   * "computer" — Windows lab machines (the PowerShell agent);
//   * "vps"      — Linux cloud servers (the lvosec Linux agent, Ubuntu/Debian
//                  VPSes such as Contabo).
// Classification is driven by the OS string the agent reports each heartbeat
// (os_label() from /etc/os-release), so it stays correct without a schema
// change.
// ---------------------------------------------------------------------------

const LINUX_OS_RE =
  /linux|ubuntu|debian|centos|rocky|almalinux|fedora|red hat|rhel|suse|opensuse|arch|manjaro|mint|kali|parrot|pop[!_]*os|elementary/i;

export type MachineKind = "computer" | "vps";

export function classifyMachineKind(os: string | null | undefined): MachineKind {
  if (!os) return "computer";
  return LINUX_OS_RE.test(os) ? "vps" : "computer";
}