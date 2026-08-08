import type { ApiClient } from "./client";
import type {
  ApiClientLimits,
  AuthAdapter,
  HeaderContextOptions,
  HttpMethod,
  ProviderConfig,
  ProviderResolver,
  RequestContext,
  ResponseParseMode,
} from "./types";

type NodeHeaderValue = string | string[] | undefined;

export type NodeLikeHeaders = Record<string, NodeHeaderValue>;

export interface NodeLikeRequest {
  method?: string;
  path?: string;
  url?: string;
  originalUrl?: string;
  query?: Record<string, unknown>;
  headers?: NodeLikeHeaders;
  body?: unknown;
}

export interface NodeLikeResponse {
  status?: (statusCode: number) => NodeLikeResponse;
  json?: (body: unknown) => void;
  send?: (body: unknown) => void;
  end?: (body?: unknown) => void;
  setHeader?: (name: string, value: string) => void;
  statusCode?: number;
}

export type ProxyAuthConfig =
  | { mode?: "none" }
  | {
      mode: "static-bearer";
      token: string;
      headerName?: string;
      scheme?: string;
    }
  | {
      mode: "forward-header";
      sourceHeaderName?: string;
      targetHeaderName?: string;
      passthrough?: boolean;
      scheme?: string;
    };

export interface ApiProxyServerConfig {
  providers?: Record<string, ProviderConfig>;
  providerResolver?: ProviderResolver;
  authAdapter?: AuthAdapter;
  auth?: ProxyAuthConfig;
  fetchImpl?: typeof fetch;
  defaultTimeoutMs?: number;
  limits?: ApiClientLimits;
  routePrefix?: string;
  defaultProviderId?: string;
  providerQueryParam?: string;
  pathQueryParam?: string;
  allowedMethods?: HttpMethod[];
  /** Simple path-prefix allowlist. At least this or allowTargetPath is required. */
  allowedPathPrefixes?: string[];
  /** Explicit compatibility escape hatch for trusted, authenticated deployments. */
  dangerouslyAllowAnyTargetPath?: boolean;
  /** Expose bounded upstream response details. Disabled by default. */
  exposeUpstreamErrorDetails?: boolean;
  forwardHeaders?: string[];
  parseAs?: ResponseParseMode;
  headerContext?: HeaderContextOptions;
  contextResolver?: (
    input: { kind: "web"; request: Request } | { kind: "node"; request: NodeLikeRequest },
  ) => RequestContext | undefined | Promise<RequestContext | undefined>;
  allowTargetPath?: (input: {
    providerId: string;
    targetPath: string;
    method: HttpMethod;
    context?: RequestContext;
  }) => boolean;
}

export interface SerializedResponse {
  status: number;
  headers: Record<string, string>;
  body: string | Uint8Array;
}

export interface ApiProxyServer {
  client: ApiClient;
  handleWebRequest(request: Request): Promise<Response>;
  handleNodeRequest(request: NodeLikeRequest): Promise<SerializedResponse>;
  createExpressMiddleware(): (
    req: NodeLikeRequest,
    res: NodeLikeResponse,
    next?: (error?: unknown) => void,
  ) => Promise<void>;
  createFastifyHandler(): (request: NodeLikeRequest, reply: NodeLikeResponse) => Promise<void>;
  createNestHandler(): (request: NodeLikeRequest, response: NodeLikeResponse) => Promise<void>;
  createHonoHandler(): (context: { req: { raw: Request } }) => Promise<Response>;
  createNextRouteHandlers(): {
    GET: (request: Request) => Promise<Response>;
    POST: (request: Request) => Promise<Response>;
    PUT: (request: Request) => Promise<Response>;
    DELETE: (request: Request) => Promise<Response>;
    PATCH: (request: Request) => Promise<Response>;
    HEAD: (request: Request) => Promise<Response>;
    OPTIONS: (request: Request) => Promise<Response>;
  };
}
