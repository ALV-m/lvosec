import { Monitor } from "lucide-react";

import { MachinesSection } from "./machines";

export default function MachinesPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-md bg-primary/10 text-primary">
          <Monitor className="size-5" />
        </div>
        <div className="flex flex-col gap-0.5">
          <h1 className="text-2xl font-bold">Machines</h1>
          <p className="text-sm text-muted-foreground">
            Every computer and cloud VPS across all tenants — network status and
            operator controls.
          </p>
        </div>
      </div>
      <MachinesSection />
    </div>
  );
}