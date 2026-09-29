import {
  useMutation,
  useQuery,
  useQueryClient,
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

// DB Management (Super Admin) — mirrors the api-zod schemas on the server.
// The dashboard registers Postgres connection URLs, marks one as the active
// (in-use) database, health-checks each, and pushes a manual snapshot per
// target.

export type DbConnectionStatus = "unknown" | "ok" | "error";

export interface PlatformDbConnection {
  id: number;
  name: string;
  url: string;
  note: string | null;
  isActive: boolean;
  status: DbConnectionStatus;
  lastCheckedAt: string | null;
  lastError: string | null;
  createdAt: string;
}

export interface DbConnectionsListResponse {
  connections: PlatformDbConnection[];
}

export interface DbConnectionCreateInput {
  name: string;
  url: string;
  note?: string;
}

export interface DbConnectionUpdateInput {
  name?: string;
  url?: string;
  note?: string | null;
  isActive?: boolean;
}

export interface DbConnectionTestResponse {
  ok: boolean;
  latencyMs: number | null;
  error: string | null;
}

export interface DbConnectionSnapshotResponse {
  ok: boolean;
  rows: number;
  takenAt: string;
}

export const getDbConnectionsUrl = (): string => "/api/admin/databases";

export const listDbConnections = async (
  options?: Parameters<typeof customFetch>[1],
): Promise<DbConnectionsListResponse> => {
  return customFetch<DbConnectionsListResponse>(getDbConnectionsUrl(), {
    ...options,
    method: "GET",
  });
};

export const getDbConnectionsQueryKey = () => ["/api/admin/databases"] as const;

export const getDbConnectionsQueryOptions = <
  TData = Awaited<ReturnType<typeof listDbConnections>>,
  TError = ErrorType<unknown>,
>(
  options?: {
    query?: UseQueryOptions<
      Awaited<ReturnType<typeof listDbConnections>>,
      TError,
      TData
    >;
    request?: SecondParameter<typeof customFetch>;
  },
) => {
  const { query: queryOptions, request: requestOptions } = options ?? {};
  const queryKey = getDbConnectionsQueryKey();
  const queryFn: QueryFunction<Awaited<ReturnType<typeof listDbConnections>>> =
    ({ signal }) => listDbConnections({ signal, ...requestOptions });
  return { queryKey, queryFn, ...queryOptions } as UseQueryOptions<
    Awaited<ReturnType<typeof listDbConnections>>,
    TError,
    TData
  > & { queryKey: QueryKey };
};

export function useGetDbConnections<
  TData = Awaited<ReturnType<typeof listDbConnections>>,
  TError = ErrorType<unknown>,
>(
  options?: {
    query?: UseQueryOptions<
      Awaited<ReturnType<typeof listDbConnections>>,
      TError,
      TData
    >;
    request?: SecondParameter<typeof customFetch>;
  },
): UseQueryResult<TData, TError> {
  return useQuery(getDbConnectionsQueryOptions(options));
}

export const createDbConnection = async (
  data: DbConnectionCreateInput,
  options?: Parameters<typeof customFetch>[1],
): Promise<PlatformDbConnection> => {
  return customFetch<PlatformDbConnection>(getDbConnectionsUrl(), {
    ...options,
    method: "POST",
    headers: { "Content-Type": "application/json", ...options?.headers },
    body: JSON.stringify(data),
  });
};

export const updateDbConnection = async (
  id: number,
  data: DbConnectionUpdateInput,
  options?: Parameters<typeof customFetch>[1],
): Promise<PlatformDbConnection> => {
  return customFetch<PlatformDbConnection>(`${getDbConnectionsUrl()}/${id}`, {
    ...options,
    method: "PATCH",
    headers: { "Content-Type": "application/json", ...options?.headers },
    body: JSON.stringify(data),
  });
};

export const deleteDbConnection = async (
  id: number,
  options?: Parameters<typeof customFetch>[1],
): Promise<{ ok: boolean }> => {
  return customFetch<{ ok: boolean }>(`${getDbConnectionsUrl()}/${id}`, {
    ...options,
    method: "DELETE",
  });
};

export const testDbConnection = async (
  id: number,
  options?: Parameters<typeof customFetch>[1],
): Promise<DbConnectionTestResponse> => {
  return customFetch<DbConnectionTestResponse>(
    `${getDbConnectionsUrl()}/${id}/test`,
    { ...options, method: "POST" },
  );
};

export const pushDbSnapshot = async (
  id: number,
  options?: Parameters<typeof customFetch>[1],
): Promise<DbConnectionSnapshotResponse> => {
  return customFetch<DbConnectionSnapshotResponse>(
    `${getDbConnectionsUrl()}/${id}/push-snapshot`,
    { ...options, method: "POST" },
  );
};

export function useCreateDbConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: DbConnectionCreateInput) => createDbConnection(data),
    onSuccess: () => void qc.invalidateQueries({ queryKey: getDbConnectionsQueryKey() }),
  });
}

export function useUpdateDbConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: DbConnectionUpdateInput }) =>
      updateDbConnection(id, data),
    onSuccess: () => void qc.invalidateQueries({ queryKey: getDbConnectionsQueryKey() }),
  });
}

export function useDeleteDbConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => deleteDbConnection(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: getDbConnectionsQueryKey() }),
  });
}

export function useTestDbConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => testDbConnection(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: getDbConnectionsQueryKey() }),
  });
}

export function usePushDbSnapshot() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => pushDbSnapshot(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: getDbConnectionsQueryKey() }),
  });
}