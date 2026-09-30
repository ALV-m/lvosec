import { Database } from "lucide-react";

import { DbManagementSection } from "./db-management";

export default function DatabasesPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-md bg-primary/10 text-primary">
          <Database className="size-5" />
        </div>
        <div className="flex flex-col gap-0.5">
          <h1 className="text-2xl font-bold">Databases</h1>
          <p className="text-sm text-muted-foreground">
            Inspect and snapshot tenant schemas across the platform.
          </p>
        </div>
      </div>
      <DbManagementSection />
    </div>
  );
}