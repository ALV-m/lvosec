import { Radar } from "lucide-react";

import { BlueTeamSection } from "./blue-team";

export default function BlueTeamPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-md bg-primary/10 text-primary">
          <Radar className="size-5" />
        </div>
        <div className="flex flex-col gap-0.5">
          <h1 className="text-2xl font-bold">Blue Team</h1>
          <p className="text-sm text-muted-foreground">
            The SOC seat: platform-wide posture, defense stack, and VPS
            protection for the Linux servers running on it.
          </p>
        </div>
      </div>
      <BlueTeamSection />
    </div>
  );
}