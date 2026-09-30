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

// Platform-wide Machines (Super Admin) — mirrors lib/api-zod admin schemas.
// One view of every tenant's computers/servers with network status and the
// same operator controls the per-lab dashboard uses.

export interface PlatformService {
  name: string;
  active?: string | null;
  sub?: string | null;
  enabled?: string | null;
}

export interface PlatformPackage {
  name: string;
  version?: string | null;
}

export interface PlatformAuthFailures {
  count24h?: number | null;
  topSources?: Array<{ ip?: string; count?: number }> | null;
}

export interface PlatformFimState {
  status?: "clean" | "drift" | null;
  changed?: Array<{ path?: string; hash?: string }> | null;
}

export interface PlatformMachine {
  tenantId: number;
  tenantName: string;
  tenantSlug: string;
  tenantStatus: string;
  id: number;
  name: string;
  room: string;
  status: string;
  userName: string | null;
  lastSeen: string;
  os: string | null;
  // "computer" = Windows lab machine · "vps" = Linux cloud server.
  kind: "computer" | "vps";
  agentVersion: string | null;
  usbState: string;
  avEnabled: boolean | null;
  firewallEnabled: boolean | null;
  firewallProfiles: string | null;
  ipAddress: string | null;
  macAddress: string | null;
  // VPS (Linux agent) telemetry from the hourly channel.
  services?: PlatformService[] | null;
  packages?: PlatformPackage[] | null;
  authFailures?: PlatformAuthFailures | null;
  fimState?: PlatformFimState | null;
  sshRateLimited: boolean | null;
}

export interface PlatformMachinesListResponse {
  machines: PlatformMachine[];
}

export type PlatformMachineAction =
  | "lock"
  | "unlock"
  | "restart"
  | "wake"
  | "send_message"
  | "block_usb"
  | "allow_usb"
  | "fw_enable"
  | "fw_disable"
  // VPS (Linux agent): service management + SSH rate limiting.
  | "service_start"
  | "service_stop"
  | "service_restart"
  | "service_enable"
  | "service_disable"
  | "fw_limit_ssh"
  | "fw_unlimit_ssh";

export interface PlatformMachineActionResponse {
  id: number;
  computerId: number;
  action: string;
  status: "queued" | "sent" | "acknowledged" | "failed";
  message: string | null;
  createdAt: string;
}

export const getAdminMachinesUrl = (): string => "/api/admin/machines";

export const listAdminMachines = async (
  options?: Parameters<typeof customFetch>[1],
): Promise<PlatformMachinesListResponse> => {
  return customFetch<PlatformMachinesListResponse>(getAdminMachinesUrl(), {
    ...options,
    method: "GET",
  });
};

export const getAdminMachinesQueryKey = () => ["/api/admin/machines"] as const;

export function useGetAdminMachines<
  TData = Awaited<ReturnType<typeof listAdminMachines>>,
  TError = ErrorType<unknown>,
>(
  options?: {
    query?: UseQueryOptions<
      Awaited<ReturnType<typeof listAdminMachines>>,
      TError,
      TData
    >;
    request?: SecondParameter<typeof customFetch>;
  },
): UseQueryResult<TData, TError> {
  const { query: queryOptions, request: requestOptions } = options ?? {};
  const queryKey = getAdminMachinesQueryKey();
  const queryFn: QueryFunction<Awaited<ReturnType<typeof listAdminMachines>>> =
    ({ signal }) => listAdminMachines({ signal, ...requestOptions });
  return useQuery({ queryKey, queryFn, ...queryOptions });
}

export const runAdminMachineAction = async (
  tenantId: number,
  computerId: number,
  data: { action: PlatformMachineAction; message?: string; payload?: Record<string, unknown> },
  options?: Parameters<typeof customFetch>[1],
): Promise<PlatformMachineActionResponse> => {
  return customFetch<PlatformMachineActionResponse>(
    `${getAdminMachinesUrl()}/${tenantId}/${computerId}/actions`,
    {
      ...options,
      method: "POST",
      headers: { "Content-Type": "application/json", ...options?.headers },
      body: JSON.stringify({
        action: data.action,
        message: data.message,
        // Service actions carry {"service": "name"} as a JSON payload string.
        ...(data.payload !== undefined ? { payload: JSON.stringify(data.payload) } : {}),
      }),
    },
  );
};

export function useRunAdminMachineAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      tenantId,
      computerId,
      data,
    }: {
      tenantId: number;
      computerId: number;
      data: { action: PlatformMachineAction; message?: string; payload?: Record<string, unknown> };
    }) => runAdminMachineAction(tenantId, computerId, data),
    onSuccess: () =>
      void qc.invalidateQueries({ queryKey: getAdminMachinesQueryKey() }),
  });
}