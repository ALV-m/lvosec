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

// These mirror the posture engine types on the server
// (artifacts/api-server/src/lib/blue-team/posture.ts). Kept here so the
// dashboard renders against a typed response without the client package having
// to import the server package.

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

export interface PostureComputerRow {
  computerId: number;
  computerName: string;
  room: string;
  status: string;
  os: string | null;
  summary: PostureSummary;
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

export interface PostureResponse {
  lab: PostureLab;
  findings: LabFinding[];
  computers: PostureComputerRow[];
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

export interface BlueTeamSearchHit {
  kind: "event" | "action" | "alert" | "checkin";
  id: number | string;
  title: string;
  detail: string;
  severity: string | null;
  computerName: string | null;
  createdAt: Date | string;
}

export interface BlueTeamSearchResponse {
  query: string;
  count: number;
  results: BlueTeamSearchHit[];
}

export const getBlueTeamPostureUrl = (): string => "/api/blue-team/posture";

export const getBlueTeamPosture = async (
  options?: Parameters<typeof customFetch>[1],
): Promise<PostureResponse> => {
  return customFetch<PostureResponse>(getBlueTeamPostureUrl(), {
    ...options,
    method: "GET",
  });
};

export const getBlueTeamPostureQueryKey = () => ["/api/blue-team/posture"] as const;

export const getBlueTeamPostureQueryOptions = <
  TData = Awaited<ReturnType<typeof getBlueTeamPosture>>,
  TError = ErrorType<unknown>,
>(
  options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getBlueTeamPosture>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
  },
) => {
  const { query: queryOptions, request: requestOptions } = options ?? {};
  const queryKey = queryOptions?.queryKey ?? getBlueTeamPostureQueryKey();
  const queryFn: QueryFunction<Awaited<ReturnType<typeof getBlueTeamPosture>>> = ({ signal }) =>
    getBlueTeamPosture({ signal, ...requestOptions });
  return { queryKey, queryFn, ...queryOptions } as UseQueryOptions<
    Awaited<ReturnType<typeof getBlueTeamPosture>>,
    TError,
    TData
  > & { queryKey: QueryKey };
};

export type GetBlueTeamPostureQueryResult = NonNullable<Awaited<ReturnType<typeof getBlueTeamPosture>>>;
export type GetBlueTeamPostureQueryError = ErrorType<unknown>;

export function useGetBlueTeamPosture<
  TData = Awaited<ReturnType<typeof getBlueTeamPosture>>,
  TError = ErrorType<unknown>,
>(
  options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getBlueTeamPosture>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
  },
): UseQueryResult<TData, TError> & { queryKey: QueryKey } {
  const queryOptions = getBlueTeamPostureQueryOptions(options);
  const query = useQuery(queryOptions) as UseQueryResult<TData, TError> & { queryKey: QueryKey };
  return query;
}

export const getBlueTeamComputerPostureUrl = (computerId: number): string =>
  `/api/blue-team/posture/${computerId}`;

export const getBlueTeamComputerPosture = async (
  computerId: number,
  options?: Parameters<typeof customFetch>[1],
): Promise<{ computer: PostureComputerRow; summary: PostureSummary }> => {
  return customFetch<{ computer: PostureComputerRow; summary: PostureSummary }>(
    getBlueTeamComputerPostureUrl(computerId),
    { ...options, method: "GET" },
  );
};

export const getBlueTeamComputerPostureQueryKey = (computerId: number) =>
  [`/api/blue-team/posture/${computerId}`] as const;

export function useGetBlueTeamComputerPosture<
  TData = Awaited<ReturnType<typeof getBlueTeamComputerPosture>>,
  TError = ErrorType<unknown>,
>(
  computerId: number,
  options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getBlueTeamComputerPosture>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
  },
): UseQueryResult<TData, TError> {
  const { query: queryOptions, request: requestOptions } = options ?? {};
  const queryKey = getBlueTeamComputerPostureQueryKey(computerId);
  const queryFn: QueryFunction<Awaited<ReturnType<typeof getBlueTeamComputerPosture>>> = ({ signal }) =>
    getBlueTeamComputerPosture(computerId, { signal, ...requestOptions });
  return useQuery({ queryKey, queryFn, ...queryOptions });
}

export const getBlueTeamSearchUrl = (q: string): string =>
  `/api/blue-team/search?q=${encodeURIComponent(q)}`;

export const searchBlueTeamRecords = async (
  q: string,
  options?: Parameters<typeof customFetch>[1],
): Promise<BlueTeamSearchResponse> => {
  return customFetch<BlueTeamSearchResponse>(getBlueTeamSearchUrl(q), {
    ...options,
    method: "GET",
  });
};