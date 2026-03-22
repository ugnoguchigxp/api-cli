export type Primitive = string | number | boolean | null;
export type QueryValue = Primitive | Primitive[];

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";

export type ResponseParseMode = "auto" | "json" | "text" | "raw";

export interface RequestContext {
  tenantId?: string;
  userId?: string;
  requestId?: string;
  metadata?: Record<string, unknown>;
}

export interface ProviderConfig {
  id: string;
  baseUrl: string;
  defaultHeaders?: Record<string, string>;
  timeoutMs?: number;
}

export type ProviderResolver = (
  providerId: string,
  context?: RequestContext,
) => ProviderConfig | null | undefined | Promise<ProviderConfig | null | undefined>;

export interface ResolvedAuthHeader {
  headerName: string;
  headerValue: string;
}

export interface AuthAdapter {
  resolveAuthHeader(input: {
    provider: ProviderConfig;
    context?: RequestContext;
  }): Promise<ResolvedAuthHeader | null> | ResolvedAuthHeader | null;
}

export interface ApiClientOptions {
  providerResolver: ProviderResolver;
  authAdapter?: AuthAdapter;
  fetchImpl?: typeof fetch;
  defaultTimeoutMs?: number;
}

export interface ApiCallRequest {
  providerId: string;
  method: HttpMethod;
  path: string;
  query?: Record<string, QueryValue | undefined>;
  headers?: Record<string, string>;
  body?: unknown;
  context?: RequestContext;
  timeoutMs?: number;
  parseAs?: ResponseParseMode;
}

export interface ApiCallResponse<T = unknown> {
  status: number;
  headers: Record<string, string>;
  data: T;
  raw: Response;
}

export interface HeaderContextOptions {
  tenantIdHeader?: string;
  userIdHeader?: string;
  requestIdHeader?: string;
  includeRawHeadersInMetadata?: boolean;
}
