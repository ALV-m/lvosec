import {
  useQuery,
  type QueryFunction,
  type QueryKey,
  type UseQueryOptions,
  type UseQueryResult,
} from "@tanstack/react-query";

import { customFetch } from "./custom-fetch";
import type { ErrorType } from "./custom-fetch";

type AwaitedInput<T> = PromiseLike<T> | T;
type Awaited<O> = O extends AwaitedInput<infer T> ? T : never;
type SecondParameter<T extends (...args: never) => unknown> = Parameters<T>[1];

// Platform-wide Blue Team — the SOC seat lives in the Platform Admin dashboard,
// not in each tenant's comp lab. These mirror the posture engine types on the
// server (artifacts/api-server/src/lib/blue-team/posture.ts) and the platform
// aggregations in artifacts/api-server/src/routes/admin-blue-team.ts.

export type PostureSeverity = "critical" | "high" | "medium" | "low" | "info";
export type PostureState = "pass" | "fail" | "unknown";
export type PostureCategory =
  | "detection"
  | "endpoint"
  | "network"
  | "access_control"
  | "data_protection"
  | "configuration";

export interface PostureFinding {
  id: string;
  title: string;
  severity: PostureSeverity;
  state: PostureState;
  detail: string;
  remediation: string;
  category: PostureCategory;
}

export interface PostureSummary {
  findings: PostureFinding[];
  evaluated: number;
  total: number;
  bySeverity: Record<PostureSeverity, number>;
  failing: number;
  headline: PostureFinding | null;
}

export interface PostureLab {
  computers: number;
  withFailures: number;
  checks: number;
  passing: number;
  failing: number;
  unknown: number;
  byCategory: Record<
    PostureCategory,
    { passing: number; failing: number; unknown: number }
  >;
  criticalMachines: Array<{
    computerId: number;
    computerName: string;
    room: string;
    headline: PostureFinding;
  }>;
}

export interface LabFinding {
  id: string;
  title: string;
  severity: PostureSeverity;
  detail: string;
  remediation: string;
  category: PostureCategory;
  affected: number;
  total: number;
  computerIds: number[];
}

export interface PlatformPostureComputerRow {
  tenantId: number;
  tenantName: string;
  tenantSlug: string;
  computerId: number;
  computerName: string;
  room: string;
  status: string;
  os: string | null;
  summary: PostureSummary;
}

export interface PostureResponse {
  lab: PostureLab;
  findings: LabFinding[];
  computers: PlatformPostureComputerRow[];
}

export const getAdminBlueTeamPostureUrl = (): string =>
  "/api/admin/blue-team/posture";

export const getAdminBlueTeamPosture = async (
  options?: Parameters<typeof customFetch>[1],
): Promise<PostureResponse> => {
  return customFetch<PostureResponse>(getAdminBlueTeamPostureUrl(), {
    ...options,
    method: "GET",
  });
};

export const getAdminBlueTeamPostureQueryKey = () =>
  ["/api/admin/blue-team/posture"] as const;

export const getAdminBlueTeamPostureQueryOptions = <
  TData = Awaited<ReturnType<typeof getAdminBlueTeamPosture>>,
  TError = ErrorType<unknown>,
>(
  options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getAdminBlueTeamPosture>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
  },
) => {
  const { query: queryOptions, request: requestOptions } = options ?? {};
  const queryKey = queryOptions?.queryKey ?? getAdminBlueTeamPostureQueryKey();
  const queryFn: QueryFunction<Awaited<ReturnType<typeof getAdminBlueTeamPosture>>> = ({
    signal,
  }) => getAdminBlueTeamPosture({ signal, ...requestOptions });
  return { queryKey, queryFn, ...queryOptions } as UseQueryOptions<
    Awaited<ReturnType<typeof getAdminBlueTeamPosture>>,
    TError,
    TData
  > & { queryKey: QueryKey };
};

export type GetAdminBlueTeamPostureQueryResult = NonNullable<
  Awaited<ReturnType<typeof getAdminBlueTeamPosture>>
>;
export type GetAdminBlueTeamPostureQueryError = ErrorType<unknown>;

export function useGetAdminBlueTeamPosture<
  TData = Awaited<ReturnType<typeof getAdminBlueTeamPosture>>,
  TError = ErrorType<unknown>,
>(
  options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getAdminBlueTeamPosture>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
  },
): UseQueryResult<TData, TError> & { queryKey: QueryKey } {
  const queryOptions = getAdminBlueTeamPostureQueryOptions(options);
  const query = useQuery(queryOptions) as UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
  };
  return query;
}

export interface BlueTeamSearchHit {
  kind: "event" | "action" | "alert" | "checkin";
  id: number | string;
  title: string;
  detail: string;
  severity: string | null;
  computerName: string | null;
  createdAt: Date | string;
  tenantName: string;
}

export interface BlueTeamSearchResponse {
  query: string;
  count: number;
  results: BlueTeamSearchHit[];
}

export const getAdminBlueTeamSearchUrl = (q: string): string =>
  `/api/admin/blue-team/search?q=${encodeURIComponent(q)}`;

export const searchAdminBlueTeamRecords = async (
  q: string,
  options?: Parameters<typeof customFetch>[1],
): Promise<BlueTeamSearchResponse> => {
  return customFetch<BlueTeamSearchResponse>(getAdminBlueTeamSearchUrl(q), {
    ...options,
    method: "GET",
  });
};

export interface SoftwareEntry {
  name: string;
  version?: string | null;
  publisher?: string | null;
}

export interface SoftwareInventoryResponse {
  machines: number;
  totalEntries: number;
  inventories: Array<{
    tenantId: number;
    tenantName: string;
    computerId: number;
    computerName: string;
    room: string;
    software: SoftwareEntry[];
  }>;
}

export const getAdminBlueTeamSoftwareUrl = (): string =>
  "/api/admin/blue-team/software";

export const getAdminBlueTeamSoftware = async (
  options?: Parameters<typeof customFetch>[1],
): Promise<SoftwareInventoryResponse> => {
  return customFetch<SoftwareInventoryResponse>(getAdminBlueTeamSoftwareUrl(), {
    ...options,
    method: "GET",
  });
};

export const getAdminBlueTeamSoftwareQueryKey = () =>
  ["/api/admin/blue-team/software"] as const;

export function useGetAdminBlueTeamSoftware(
  options?: { request?: SecondParameter<typeof customFetch> },
) {
  const queryKey = getAdminBlueTeamSoftwareQueryKey();
  const queryFn: QueryFunction<Awaited<ReturnType<typeof getAdminBlueTeamSoftware>>> = ({
    signal,
  }) => getAdminBlueTeamSoftware({ signal, ...options?.request });
  return useQuery({ queryKey, queryFn });
}

// Defense Stack — live status of every defensive layer (perimeter/WAF,
// detection, hosts, assets, databases, data) mapped 1:1 to the SOC blueprint,
// aggregated across the whole platform.

export type DefenseLayerState = "active" | "warning" | "off" | "na";

export interface DefenseLayer {
  id: string;
  label: string;
  state: DefenseLayerState;
  detail: string;
  count: number | null;
}

export interface DefenseStackResponse {
  layers: DefenseLayer[];
  lab: { computers: number; failing: number };
  findings: number;
}

export const getAdminBlueTeamDefenseStackUrl = (): string =>
  "/api/admin/blue-team/defense-stack";

export const getAdminBlueTeamDefenseStack = async (
  options?: Parameters<typeof customFetch>[1],
): Promise<DefenseStackResponse> => {
  return customFetch<DefenseStackResponse>(getAdminBlueTeamDefenseStackUrl(), {
    ...options,
    method: "GET",
  });
};

export const getAdminBlueTeamDefenseStackQueryKey = () =>
  ["/api/admin/blue-team/defense-stack"] as const;

export function useGetAdminBlueTeamDefenseStack(
  options?: { request?: SecondParameter<typeof customFetch> },
) {
  const queryKey = getAdminBlueTeamDefenseStackQueryKey();
  const queryFn: QueryFunction<
    Awaited<ReturnType<typeof getAdminBlueTeamDefenseStack>>
  > = ({ signal }) => getAdminBlueTeamDefenseStack({ signal, ...options?.request });
  return useQuery({ queryKey, queryFn });
}