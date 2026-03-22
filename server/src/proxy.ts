import { createBearerAuthAdapter, createStaticProviderResolver } from "./adapters";
import { ApiClient } from "./client";
import { createContextFromNodeRequest, createContextFromWebRequest } from "./context";
import { ApiCliError, ApiCliHttpError } from "./errors";
import type {
  ApiCallRequest,
  ApiCallResponse,
  AuthAdapter,
  HeaderContextOptions,
  HttpMethod,
  ProviderConfig,
  ProviderResolver,
  QueryValue,
  RequestContext,
  ResponseParseMode,
} from "./types";

const DEFAULT_ALLOWED_METHODS: HttpMethod[] = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
];

const DEFAULT_FORWARD_HEADERS = ["x-request-id", "x-tenant-id", "x-user-id"];

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
  | {
      mode?: "none";
    }
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
  routePrefix?: string;
  defaultProviderId?: string;
  providerQueryParam?: string;
  pathQueryParam?: string;
  allowedMethods?: HttpMethod[];
  forwardHeaders?: string[];
  parseAs?: ResponseParseMode;
  headerContext?: HeaderContextOptions;
  contextResolver?: (
    input:
      | {
          kind: "web";
          request: Request;
        }
      | {
          kind: "node";
          request: NodeLikeRequest;
        },
  ) => RequestContext | undefined | Promise<RequestContext | undefined>;
  allowTargetPath?: (input: {
    providerId: string;
    targetPath: string;
    method: HttpMethod;
    context?: RequestContext;
  }) => boolean;
}

interface SerializedResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

type QueryMultiMap = Record<string, string[]>;

function normalizeRoutePrefix(prefix: string | undefined): string {
  const fallback = "/apicli";
  const raw = prefix && prefix.trim().length > 0 ? prefix.trim() : fallback;
  if (raw === "/") {
    return "/";
  }

  let normalized = raw.startsWith("/") ? raw : `/${raw}`;
  if (normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

function stripRoutePrefix(pathname: string, routePrefix: string): string {
  const normalizedPath = pathname.startsWith("/") ? pathname : `/${pathname}`;
  if (routePrefix === "/") {
    return normalizedPath;
  }

  if (normalizedPath === routePrefix) {
    return "/";
  }

  if (normalizedPath.startsWith(`${routePrefix}/`)) {
    return normalizedPath.slice(routePrefix.length);
  }

  const middle = normalizedPath.indexOf(`${routePrefix}/`);
  if (middle >= 0) {
    return normalizedPath.slice(middle + routePrefix.length);
  }

  return normalizedPath;
}

function getHeaderValue(
  headers: Headers | NodeLikeHeaders,
  headerName: string,
): string | undefined {
  if (headers instanceof Headers) {
    return headers.get(headerName) ?? undefined;
  }

  const lower = headerName.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== lower) {
      continue;
    }

    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }

  return undefined;
}

function pickForwardHeaders(
  headers: Headers | NodeLikeHeaders,
  allowList: string[],
): Record<string, string> {
  const picked: Record<string, string> = {};

  for (const name of allowList) {
    const value = getHeaderValue(headers, name);
    if (value) {
      picked[name] = value;
    }
  }

  return picked;
}

function toHttpMethod(method: string | undefined): HttpMethod | null {
  if (!method) {
    return null;
  }

  const normalized = method.toUpperCase();
  if (DEFAULT_ALLOWED_METHODS.includes(normalized as HttpMethod)) {
    return normalized as HttpMethod;
  }

  return null;
}

function appendToQueryMap(map: QueryMultiMap, key: string, value: string): void {
  if (map[key]) {
    map[key].push(value);
  } else {
    map[key] = [value];
  }
}

function queryMapFromSearchParams(params: URLSearchParams): QueryMultiMap {
  const map: QueryMultiMap = {};
  for (const [key, value] of params.entries()) {
    appendToQueryMap(map, key, value);
  }
  return map;
}

function queryMapFromNodeQuery(query: Record<string, unknown> | undefined): QueryMultiMap {
  const map: QueryMultiMap = {};
  if (!query) {
    return map;
  }

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        appendToQueryMap(map, key, String(item));
      }
      continue;
    }

    appendToQueryMap(map, key, String(value));
  }

  return map;
}

function firstQueryValue(map: QueryMultiMap, key: string): string | undefined {
  return map[key]?.[0];
}

function buildOutboundQuery(
  queryMap: QueryMultiMap,
  reservedKeys: Set<string>,
): Record<string, QueryValue> | undefined {
  const outbound: Record<string, QueryValue> = {};

  for (const [key, values] of Object.entries(queryMap)) {
    if (reservedKeys.has(key)) {
      continue;
    }

    if (values.length === 1) {
      const single = values[0];
      if (single !== undefined) {
        outbound[key] = single;
      }
    } else if (values.length > 1) {
      outbound[key] = values;
    }
  }

  return Object.keys(outbound).length > 0 ? outbound : undefined;
}

function normalizeTargetPath(path: string): string {
  if (!path) {
    return "/";
  }

  if (path.startsWith("/")) {
    return path;
  }

  return `/${path}`;
}

function mergeContext(base: RequestContext, extra: RequestContext | undefined): RequestContext {
  if (!extra) {
    return base;
  }

  const merged: RequestContext = { ...base, ...extra };

  if (base.metadata || extra.metadata) {
    merged.metadata = {
      ...(base.metadata ?? {}),
      ...(extra.metadata ?? {}),
    };
  }

  return merged;
}

function statusFromError(error: unknown): number {
  if (error instanceof ApiCliHttpError) {
    return error.status;
  }

  if (error instanceof ApiCliError) {
    switch (error.code) {
      case "PROVIDER_NOT_FOUND":
        return 404;
      case "BAD_REQUEST":
        return 400;
      case "METHOD_NOT_ALLOWED":
        return 405;
      case "TIMEOUT":
        return 504;
      default:
        return 502;
    }
  }

  return 500;
}

function serializeErrorResponse(error: unknown): SerializedResponse {
  const status = statusFromError(error);

  if (error instanceof ApiCliHttpError) {
    const body = JSON.stringify({
      ok: false,
      error: {
        code: error.code,
        message: error.message,
        details: {
          ...(error.details ?? {}),
          upstreamStatus: error.status,
          upstreamBody: error.responseText,
          upstreamHeaders: error.responseHeaders,
        },
      },
    });

    return {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
      },
      body,
    };
  }

  if (error instanceof ApiCliError) {
    const body = JSON.stringify({
      ok: false,
      error: {
        code: error.code,
        message: error.message,
        details: error.details ?? null,
      },
    });

    return {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
      },
      body,
    };
  }

  const body = JSON.stringify({
    ok: false,
    error: {
      code: "INTERNAL",
      message: error instanceof Error ? error.message : "Unexpected error",
    },
  });

  return {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
    },
    body,
  };
}

async function serializeSuccessResponse(
  result: ApiCallResponse<unknown>,
): Promise<SerializedResponse> {
  const headers: Record<string, string> = {};
  const contentType = result.headers["content-type"] ?? result.headers["Content-Type"];

  if (result.data instanceof Response) {
    const responseHeaders = Object.fromEntries(result.data.headers.entries());
    return {
      status: result.data.status,
      headers: responseHeaders,
      body: await result.data.text(),
    };
  }

  if (typeof result.data === "string") {
    headers["content-type"] = contentType ?? "text/plain; charset=utf-8";
    return {
      status: result.status,
      headers,
      body: result.data,
    };
  }

  headers["content-type"] = contentType ?? "application/json; charset=utf-8";
  return {
    status: result.status,
    headers,
    body: JSON.stringify(result.data),
  };
}

function nodeRequestPathname(request: NodeLikeRequest): string {
  if (request.path && request.path.length > 0) {
    return request.path;
  }

  const rawUrl = request.originalUrl ?? request.url ?? "/";
  return new URL(rawUrl, "http://localhost").pathname;
}

function nodeRequestQuery(request: NodeLikeRequest): QueryMultiMap {
  if (request.query && Object.keys(request.query).length > 0) {
    return queryMapFromNodeQuery(request.query);
  }

  const rawUrl = request.originalUrl ?? request.url;
  if (!rawUrl) {
    return {};
  }

  const parsed = new URL(rawUrl, "http://localhost");
  return queryMapFromSearchParams(parsed.searchParams);
}

function isBodylessMethod(method: HttpMethod): boolean {
  return method === "GET" || method === "HEAD";
}

async function parseWebBody(request: Request, method: HttpMethod): Promise<unknown | undefined> {
  if (isBodylessMethod(method)) {
    return undefined;
  }

  const raw = await request.text();
  if (raw.length === 0) {
    return undefined;
  }

  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }

  return raw;
}

function parseNodeBody(
  body: unknown,
  method: HttpMethod,
  headers: NodeLikeHeaders | undefined,
): unknown | undefined {
  if (isBodylessMethod(method)) {
    return undefined;
  }

  if (body === undefined) {
    return undefined;
  }

  if (typeof body === "string") {
    const contentType = headers
      ? (getHeaderValue(headers, "content-type") ?? "").toLowerCase()
      : "";
    if (contentType.includes("application/json")) {
      try {
        return JSON.parse(body);
      } catch {
        return body;
      }
    }
  }

  return body;
}

function resolveAuthAdapter(config: ApiProxyServerConfig): AuthAdapter | undefined {
  if (config.authAdapter) {
    return config.authAdapter;
  }

  const auth = config.auth;
  if (!auth || auth.mode === "none" || auth.mode === undefined) {
    return undefined;
  }

  if (auth.mode === "static-bearer") {
    const options: { headerName?: string; scheme?: string } = {};
    if (auth.headerName !== undefined) {
      options.headerName = auth.headerName;
    }
    if (auth.scheme !== undefined) {
      options.scheme = auth.scheme;
    }

    return createBearerAuthAdapter(() => auth.token, options);
  }

  if (auth.mode !== "forward-header") {
    return undefined;
  }

  const sourceHeaderName = auth.sourceHeaderName ?? "authorization";
  const targetHeaderName = auth.targetHeaderName ?? sourceHeaderName;
  const passthrough = auth.passthrough ?? true;
  const scheme = auth.scheme ?? "Bearer";

  return {
    async resolveAuthHeader({ context }) {
      const metadata = context?.metadata;
      const rawHeaders = metadata?.headers as Record<string, unknown> | undefined;
      if (!rawHeaders) {
        return null;
      }

      let headerValue: string | undefined;
      const sourceLower = sourceHeaderName.toLowerCase();
      for (const [key, value] of Object.entries(rawHeaders)) {
        if (key.toLowerCase() !== sourceLower || value === undefined || value === null) {
          continue;
        }

        if (Array.isArray(value)) {
          headerValue = value[0] ? String(value[0]) : undefined;
        } else {
          headerValue = String(value);
        }
        break;
      }

      if (!headerValue) {
        return null;
      }

      if (passthrough) {
        return {
          headerName: targetHeaderName,
          headerValue,
        };
      }

      const token = headerValue.replace(/^Bearer\s+/i, "").trim();
      if (!token) {
        return null;
      }

      return {
        headerName: targetHeaderName,
        headerValue: `${scheme} ${token}`,
      };
    },
  };
}

function resolveProviderResolver(config: ApiProxyServerConfig): ProviderResolver {
  if (config.providerResolver) {
    return config.providerResolver;
  }

  if (!config.providers) {
    throw new Error("Either providers or providerResolver must be provided");
  }

  return createStaticProviderResolver(config.providers);
}

function ensureAllowedMethod(method: HttpMethod, config: ApiProxyServerConfig): void {
  const allowed = config.allowedMethods ?? DEFAULT_ALLOWED_METHODS;
  if (!allowed.includes(method)) {
    throw new ApiCliError("METHOD_NOT_ALLOWED", `Method not allowed: ${method}`);
  }
}

function resolveTarget(
  pathname: string,
  query: QueryMultiMap,
  config: ApiProxyServerConfig,
): {
  providerId: string;
  targetPath: string;
  outboundQuery: Record<string, QueryValue> | undefined;
} {
  const providerKey = config.providerQueryParam ?? "provider";
  const pathKey = config.pathQueryParam ?? "path";

  const trimmedPath = stripRoutePrefix(pathname, normalizeRoutePrefix(config.routePrefix));
  const segments = trimmedPath
    .split("/")
    .map((seg) => seg.trim())
    .filter((seg) => seg.length > 0);

  const providerFromQuery = firstQueryValue(query, providerKey);
  const providerId = providerFromQuery ?? segments.shift() ?? config.defaultProviderId;
  if (!providerId) {
    throw new ApiCliError(
      "BAD_REQUEST",
      `Missing provider id. Use path '/:providerId/*' or query '${providerKey}'.`,
    );
  }

  const pathFromQuery = firstQueryValue(query, pathKey);
  const targetPath = normalizeTargetPath(pathFromQuery ?? segments.join("/"));

  const outboundQuery = buildOutboundQuery(query, new Set([providerKey, pathKey]));
  return {
    providerId,
    targetPath,
    outboundQuery,
  };
}

function buildHeaderContextOptions(config: ApiProxyServerConfig): HeaderContextOptions {
  const options: HeaderContextOptions = {
    ...(config.headerContext ?? {}),
  };

  const shouldIncludeRaw =
    config.headerContext?.includeRawHeadersInMetadata ?? config.auth?.mode === "forward-header";
  if (shouldIncludeRaw) {
    options.includeRawHeadersInMetadata = true;
  }

  return options;
}

function sendSerializedNodeResponse(
  response: NodeLikeResponse,
  serialized: SerializedResponse,
): void {
  if (response.status) {
    response.status(serialized.status);
  } else {
    response.statusCode = serialized.status;
  }

  for (const [key, value] of Object.entries(serialized.headers)) {
    response.setHeader?.(key, value);
  }

  const contentType = serialized.headers["content-type"]?.toLowerCase() ?? "";
  if (contentType.includes("application/json") && response.json) {
    try {
      response.json(JSON.parse(serialized.body));
      return;
    } catch {
      // fall through
    }
  }

  if (response.send) {
    response.send(serialized.body);
    return;
  }

  response.end?.(serialized.body);
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

export function createApiProxyServer(config: ApiProxyServerConfig): ApiProxyServer {
  const clientOptions: {
    providerResolver: ProviderResolver;
    authAdapter?: AuthAdapter;
    fetchImpl?: typeof fetch;
    defaultTimeoutMs?: number;
  } = {
    providerResolver: resolveProviderResolver(config),
  };

  const authAdapter = resolveAuthAdapter(config);
  if (authAdapter !== undefined) {
    clientOptions.authAdapter = authAdapter;
  }
  if (config.fetchImpl !== undefined) {
    clientOptions.fetchImpl = config.fetchImpl;
  }
  if (config.defaultTimeoutMs !== undefined) {
    clientOptions.defaultTimeoutMs = config.defaultTimeoutMs;
  }

  const client = new ApiClient(clientOptions);

  const executeProxy = async (input: {
    method: string | undefined;
    pathname: string;
    query: QueryMultiMap;
    headers: Headers | NodeLikeHeaders;
    body?: unknown;
    context: RequestContext;
  }): Promise<SerializedResponse> => {
    try {
      const method = toHttpMethod(input.method);
      if (!method) {
        throw new ApiCliError("METHOD_NOT_ALLOWED", `Unsupported method: ${input.method ?? ""}`);
      }
      ensureAllowedMethod(method, config);

      const { providerId, targetPath, outboundQuery } = resolveTarget(
        input.pathname,
        input.query,
        config,
      );

      if (
        config.allowTargetPath &&
        !config.allowTargetPath({
          providerId,
          targetPath,
          method,
          context: input.context,
        })
      ) {
        throw new ApiCliError("BAD_REQUEST", `Target path is not allowed: ${targetPath}`);
      }

      const forwardHeaders = pickForwardHeaders(
        input.headers,
        config.forwardHeaders ?? DEFAULT_FORWARD_HEADERS,
      );

      const request: ApiCallRequest = {
        providerId,
        method,
        path: targetPath,
        headers: forwardHeaders,
        context: input.context,
      };
      if (outboundQuery !== undefined) {
        request.query = outboundQuery;
      }
      if (config.parseAs !== undefined) {
        request.parseAs = config.parseAs;
      }

      if (input.body !== undefined) {
        request.body = input.body;
      }

      const response = await client.call(request);
      return await serializeSuccessResponse(response);
    } catch (error) {
      return serializeErrorResponse(error);
    }
  };

  const handleWebRequest = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const query = queryMapFromSearchParams(url.searchParams);

    const contextBase = createContextFromWebRequest(request, buildHeaderContextOptions(config));
    const contextExtra = config.contextResolver
      ? await config.contextResolver({ kind: "web", request })
      : undefined;
    const context = mergeContext(contextBase, contextExtra);

    const body = await parseWebBody(request, toHttpMethod(request.method) ?? "GET");
    const serialized = await executeProxy({
      method: request.method,
      pathname: url.pathname,
      query,
      headers: request.headers,
      body,
      context,
    });

    return new Response(serialized.body, {
      status: serialized.status,
      headers: serialized.headers,
    });
  };

  const handleNodeRequest = async (request: NodeLikeRequest): Promise<SerializedResponse> => {
    const method = toHttpMethod(request.method) ?? "GET";
    const contextBase = createContextFromNodeRequest(
      { headers: request.headers ?? {} },
      buildHeaderContextOptions(config),
    );
    const contextExtra = config.contextResolver
      ? await config.contextResolver({ kind: "node", request })
      : undefined;
    const context = mergeContext(contextBase, contextExtra);

    return executeProxy({
      method: request.method,
      pathname: nodeRequestPathname(request),
      query: nodeRequestQuery(request),
      headers: request.headers ?? {},
      body: parseNodeBody(request.body, method, request.headers),
      context,
    });
  };

  const createExpressMiddleware = () => {
    return async (
      req: NodeLikeRequest,
      res: NodeLikeResponse,
      next?: (error?: unknown) => void,
    ): Promise<void> => {
      try {
        const serialized = await handleNodeRequest(req);
        sendSerializedNodeResponse(res, serialized);
      } catch (error) {
        if (next) {
          next(error);
          return;
        }
        sendSerializedNodeResponse(res, serializeErrorResponse(error));
      }
    };
  };

  const createFastifyHandler = () => {
    return async (request: NodeLikeRequest, reply: NodeLikeResponse): Promise<void> => {
      const serialized = await handleNodeRequest(request);
      sendSerializedNodeResponse(reply, serialized);
    };
  };

  const createNestHandler = () => {
    return async (request: NodeLikeRequest, response: NodeLikeResponse): Promise<void> => {
      const serialized = await handleNodeRequest(request);
      sendSerializedNodeResponse(response, serialized);
    };
  };

  const createHonoHandler = () => {
    return async (context: { req: { raw: Request } }): Promise<Response> => {
      return handleWebRequest(context.req.raw);
    };
  };

  const createNextRouteHandlers = () => {
    const handler = async (request: Request): Promise<Response> => handleWebRequest(request);
    return {
      GET: handler,
      POST: handler,
      PUT: handler,
      DELETE: handler,
      PATCH: handler,
      HEAD: handler,
      OPTIONS: handler,
    };
  };

  return {
    client,
    handleWebRequest,
    handleNodeRequest,
    createExpressMiddleware,
    createFastifyHandler,
    createNestHandler,
    createHonoHandler,
    createNextRouteHandlers,
  };
}
