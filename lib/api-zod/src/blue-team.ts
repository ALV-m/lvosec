import * as zod from "zod";

// ---------------------------------------------------------------------------
// Blue Team "Defense Stack" — a live overview of every defensive layer the
// blue-team dashboard covers (perimeter/WAF, detection, assets, hosts,
// databases, data). States are derived from real runtime data, and layers in
// the blueprint that are deliberately out of scope are reported as well so
// the dashboard stays honest about its coverage.
// ---------------------------------------------------------------------------

export const DefenseLayerState = zod.enum(["active", "warning", "off", "na"]);
export type DefenseLayerState = zod.infer<typeof DefenseLayerState>;

export const DefenseLayer = zod.object({
  id: zod.string(),
  label: zod.string(),
  state: DefenseLayerState,
  detail: zod.string(),
  count: zod.number().nullable(),
});
export type DefenseLayer = zod.infer<typeof DefenseLayer>;

export const DefenseStackResponse = zod.object({
  layers: zod.array(DefenseLayer),
  lab: zod.object({
    computers: zod.number(),
    failing: zod.number(),
  }),
  findings: zod.number(),
});
export type DefenseStackResponse = zod.infer<typeof DefenseStackResponse>;