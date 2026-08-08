import { createBearerAuthAdapter, createStaticProviderResolver } from "./adapters";
import { ApiClient } from "./client";
import { createContextFromNodeRequest, createContextFromWebRequest } from "./context";
import { ApiCliError, ApiCliHttpError } from "./errors";
import type {
  ApiProxyServer,
  ApiProxyServerConfig,
  NodeLikeHeaders,
  NodeLikeRequest,
  NodeLikeResponse,
  SerializedResponse,
} from "./proxy-types";
import type {
  ApiCallRequest,
  ApiCallResponse,
  ApiClientLimits,
  AuthAdapter,
  HeaderContextOptions,
  HttpMethod,
  ProviderResolver,
  QueryValue,
  RequestContext,
} from "./types";

const DEFAULT_ALLOWED_METHODS: HttpMethod[] = ["GET", "HEAD"];
const ALL_HTTP_METHODS: HttpMethod[] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
const DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024;

const DEFAULT_FORWARD_HEADERS = ["content-type", "x-request-id", "x-tenant-id", "x-user-id"];
const FORBIDDEN_TRANSPORT_HEADERS = new Set([
  "connection",
  "content-encoding",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "set-cookie",
  "set-cookie2",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export type {
  ApiProxyServer,
  ApiProxyServerConfig,
  NodeLikeHeaders,
  NodeLikeRequest,
  NodeLikeResponse,
  ProxyAuthConfig,
  SerializedResponse,
} from "./proxy-types";

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

function isBodyForbiddenStatus(status: number): boolean {
  return status === 204 || status === 205 || status === 304;
}

function webResponseBody(serialized: SerializedResponse, suppressBody = false): BodyInit | null {
  if (suppressBody || isBodyForbiddenStatus(serialized.status)) {
    return null;
  }
  if (typeof serialized.body === "string") {
    return serialized.body;
  }
  return serialized.body.buffer.slice(
    serialized.body.byteOffset,
    serialized.body.byteOffset + serialized.body.byteLength,
  ) as ArrayBuffer;
}

function filteredResponseHeaders(headers: Headers): Record<string, string> {
  const filtered: Record<string, string> = {};
  for (const [name, value] of headers.entries()) {
    if (!FORBIDDEN_TRANSPORT_HEADERS.has(name.toLowerCase())) {
      filtered[name] = value;
    }
  }
  return filtered;
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

  return normalizedPath;
}

function isWithinRoutePrefix(pathname: string, routePrefix: string): boolean {
  return routePrefix === "/" || pathname === routePrefix || pathname.startsWith(`${routePrefix}/`);
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
  if (ALL_HTTP_METHODS.includes(normalized as HttpMethod)) {
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
    return error.status >= 400 && error.status <= 599 ? error.status : 502;
  }

  if (error instanceof ApiCliError) {
    switch (error.code) {
      case "PROVIDER_NOT_FOUND":
        return 404;
      case "BAD_REQUEST":
      case "BLOCKED_URL":
        return 400;
      case "METHOD_NOT_ALLOWED":
        return 405;
      case "REQUEST_TOO_LARGE":
        return 413;
      case "TIMEOUT":
        return 504;
      default:
        return 502;
    }
  }

  return 500;
}

function serializeErrorResponse(
  error: unknown,
  exposeUpstreamErrorDetails = false,
): SerializedResponse {
  const status = statusFromError(error);

  if (error instanceof ApiCliHttpError) {
    const details = exposeUpstreamErrorDetails
      ? {
          ...(error.details ?? {}),
          upstreamStatus: error.status,
          upstreamBody: error.responseText,
          upstreamHeaders: error.responseHeaders,
        }
      : {
          providerId: error.details?.providerId,
          method: error.details?.method,
          upstreamStatus: error.status,
        };
    const body = JSON.stringify({
      ok: false,
      error: {
        code: error.code,
        message: error.message,
        details,
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
        details: exposeUpstreamErrorDetails ? (error.details ?? null) : null,
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
      message:
        exposeUpstreamErrorDetails && error instanceof Error
          ? error.message
          : "Unexpected internal error",
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
    const responseHeaders = filteredResponseHeaders(result.data.headers);
    return {
      status: result.data.status,
      headers: responseHeaders,
      body: new Uint8Array(await result.data.arrayBuffer()),
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

  let body: string;
  try {
    const serialized = JSON.stringify(result.data);
    body = serialized === undefined ? "null" : serialized;
  } catch {
    throw new ApiCliError("INVALID_RESPONSE", "Response data is not JSON serializable");
  }
  headers["content-type"] = contentType ?? "application/json; charset=utf-8";
  return {
    status: result.status,
    headers,
    body,
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

async function readLimitedRequestBody(request: Request, limit: number): Promise<Uint8Array> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (Number.isFinite(parsed) && parsed > limit) {
      throw new ApiCliError("REQUEST_TOO_LARGE", `Request exceeded ${limit} bytes`, { limit });
    }
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        try {
          await reader.cancel();
        } catch {
          // Preserve the size-limit error if cancellation itself fails.
        }
        throw new ApiCliError("REQUEST_TOO_LARGE", `Request exceeded ${limit} bytes`, { limit });
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function isJsonContentType(contentType: string): boolean {
  const mediaType = contentType.split(";", 1)[0]?.trim() ?? "";
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

function isTextContentType(contentType: string): boolean {
  const mediaType = contentType.split(";", 1)[0]?.trim() ?? "";
  return mediaType.startsWith("text/") || mediaType === "application/x-www-form-urlencoded";
}

async function parseWebBody(
  request: Request,
  method: HttpMethod,
  maxRequestBytes: number,
): Promise<unknown | undefined> {
  if (isBodylessMethod(method)) {
    return undefined;
  }

  const raw = await readLimitedRequestBody(request, maxRequestBytes);
  if (raw.byteLength === 0) {
    return undefined;
  }

  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (isJsonContentType(contentType)) {
    try {
      return JSON.parse(new TextDecoder().decode(raw));
    } catch {
      throw new ApiCliError("BAD_REQUEST", "Request body is not valid JSON");
    }
  }

  if (isTextContentType(contentType)) {
    return new TextDecoder().decode(raw);
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
    if (isJsonContentType(contentType)) {
      try {
        return JSON.parse(body);
      } catch {
        throw new ApiCliError("BAD_REQUEST", "Request body is not valid JSON");
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
    throw new Error(`Unsupported auth mode: ${String((auth as { mode?: unknown }).mode)}`);
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

function validateProxyConfig(config: ApiProxyServerConfig): void {
  const routePrefix = normalizeRoutePrefix(config.routePrefix);
  validateConfiguredPath(routePrefix, "routePrefix");
  if (config.allowedMethods !== undefined) {
    if (config.allowedMethods.length === 0) {
      throw new Error("allowedMethods cannot be empty");
    }
    const methods = new Set<string>();
    for (const method of config.allowedMethods) {
      if (!ALL_HTTP_METHODS.includes(method) || methods.has(method)) {
        throw new Error(`Invalid or duplicate allowed method: ${method}`);
      }
      methods.add(method);
    }
  }
  if (
    config.dangerouslyAllowAnyTargetPath !== true &&
    !config.allowTargetPath &&
    (!config.allowedPathPrefixes || config.allowedPathPrefixes.length === 0)
  ) {
    throw new Error(
      "A path policy is required: configure allowedPathPrefixes or allowTargetPath, or explicitly set dangerouslyAllowAnyTargetPath",
    );
  }
  for (const prefix of config.allowedPathPrefixes ?? []) {
    validateConfiguredPath(prefix, "allowed path prefix");
  }
  if ((config.allowedPathPrefixes?.length ?? 0) > 128) {
    throw new Error("allowedPathPrefixes cannot contain more than 128 entries");
  }
  const seenHeaders = new Set<string>();
  for (const header of config.forwardHeaders ?? []) {
    const normalized = header.toLowerCase();
    try {
      new Headers({ [header]: "value" });
    } catch {
      throw new Error(`Invalid forwarded header: ${header}`);
    }
    if (FORBIDDEN_TRANSPORT_HEADERS.has(normalized)) {
      throw new Error(`Forbidden forwarded header: ${header}`);
    }
    if (seenHeaders.has(normalized)) {
      throw new Error(`Duplicate forwarded header: ${header}`);
    }
    seenHeaders.add(normalized);
  }
  const providerKey = config.providerQueryParam ?? "provider";
  const pathKey = config.pathQueryParam ?? "path";
  if (
    !isSafeQueryKey(providerKey) ||
    !isSafeQueryKey(pathKey) ||
    providerKey.toLowerCase() === pathKey.toLowerCase()
  ) {
    throw new Error("providerQueryParam and pathQueryParam must be non-empty and distinct");
  }
  if (config.defaultProviderId !== undefined && config.defaultProviderId.length > 256) {
    throw new Error("defaultProviderId cannot exceed 256 characters");
  }
  if (config.auth?.mode === "static-bearer") {
    if (config.auth.token.length === 0) {
      throw new Error("static bearer token cannot be empty");
    }
    validateHeaderName(config.auth.headerName ?? "authorization", "auth header");
    validateHeaderValue(`${config.auth.scheme ?? "Bearer"} ${config.auth.token}`, "auth value");
  }
  if (config.auth?.mode === "forward-header") {
    const source = config.auth.sourceHeaderName ?? "authorization";
    validateHeaderName(source, "source auth header");
    validateHeaderName(config.auth.targetHeaderName ?? source, "target auth header");
    if (config.auth.passthrough === false) {
      validateHeaderValue(`${config.auth.scheme ?? "Bearer"} token`, "auth scheme");
    }
  }
}

function isSafeQueryKey(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 128 &&
    !Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x20 || codePoint === 0x7f || character === "&" || character === "=";
    })
  );
}

function validateHeaderName(name: string, label: string): void {
  try {
    new Headers({ [name]: "value" });
  } catch {
    throw new Error(`Invalid ${label}: ${name}`);
  }
}

function validateHeaderValue(value: string, label: string): void {
  try {
    new Headers({ "x-apicli-validation": value });
  } catch {
    throw new Error(`Invalid ${label}`);
  }
}

function validateConfiguredPath(path: string, name: string): void {
  if (
    path.length > 2048 ||
    !path.startsWith("/") ||
    path.includes("\\") ||
    path.includes("?") ||
    path.includes("#")
  ) {
    throw new Error(`Invalid ${name}: ${path}`);
  }
  for (const rawSegment of path.split("/")) {
    let segment: string;
    try {
      segment = decodeURIComponent(rawSegment);
    } catch {
      throw new Error(`Invalid ${name}: ${path}`);
    }
    const hasControl = Array.from(segment).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f;
    });
    if (
      segment === "." ||
      segment === ".." ||
      segment.includes("/") ||
      segment.includes("\\") ||
      hasControl
    ) {
      throw new Error(`Invalid ${name}: ${path}`);
    }
  }
}

function isTargetPathAllowed(
  config: ApiProxyServerConfig,
  input: {
    providerId: string;
    targetPath: string;
    method: HttpMethod;
    context: RequestContext;
  },
): boolean {
  if (config.dangerouslyAllowAnyTargetPath === true) return true;
  if (config.allowTargetPath && !config.allowTargetPath(input)) return false;
  const prefixes = config.allowedPathPrefixes;
  if (!prefixes || prefixes.length === 0) return config.allowTargetPath !== undefined;
  return prefixes.some(
    (prefix) =>
      input.targetPath === prefix || input.targetPath.startsWith(`${prefix.replace(/\/$/, "")}/`),
  );
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
  suppressBody = false,
): void {
  if (response.status) {
    response.status(serialized.status);
  } else {
    response.statusCode = serialized.status;
  }

  for (const [key, value] of Object.entries(serialized.headers)) {
    response.setHeader?.(key, value);
  }

  if (suppressBody || isBodyForbiddenStatus(serialized.status)) {
    response.end?.();
    return;
  }

  const contentType = serialized.headers["content-type"]?.toLowerCase() ?? "";
  if (
    typeof serialized.body === "string" &&
    contentType.includes("application/json") &&
    response.json
  ) {
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

export function createApiProxyServer(config: ApiProxyServerConfig): ApiProxyServer {
  validateProxyConfig(config);
  const clientOptions: {
    providerResolver: ProviderResolver;
    authAdapter?: AuthAdapter;
    fetchImpl?: typeof fetch;
    defaultTimeoutMs?: number;
    limits?: ApiClientLimits;
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
  if (config.limits !== undefined) {
    clientOptions.limits = config.limits;
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
        !isTargetPathAllowed(config, {
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
      return serializeErrorResponse(error, config.exposeUpstreamErrorDetails === true);
    }
  };

  const handleWebRequest = async (request: Request): Promise<Response> => {
    try {
      const url = new URL(request.url);
      const routePrefix = normalizeRoutePrefix(config.routePrefix);
      if (!isWithinRoutePrefix(url.pathname, routePrefix)) {
        throw new ApiCliError("BAD_REQUEST", "Request path is outside the proxy route prefix");
      }
      const query = queryMapFromSearchParams(url.searchParams);
      const contextBase = createContextFromWebRequest(request, buildHeaderContextOptions(config));
      const contextExtra = config.contextResolver
        ? await config.contextResolver({ kind: "web", request })
        : undefined;
      const context = mergeContext(contextBase, contextExtra);
      const body = await parseWebBody(
        request,
        toHttpMethod(request.method) ?? "GET",
        config.limits?.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES,
      );
      const serialized = await executeProxy({
        method: request.method,
        pathname: url.pathname,
        query,
        headers: request.headers,
        body,
        context,
      });

      return new Response(webResponseBody(serialized, request.method.toUpperCase() === "HEAD"), {
        status: serialized.status,
        headers: serialized.headers,
      });
    } catch (error) {
      const serialized = serializeErrorResponse(error, config.exposeUpstreamErrorDetails === true);
      return new Response(webResponseBody(serialized, request.method.toUpperCase() === "HEAD"), {
        status: serialized.status,
        headers: serialized.headers,
      });
    }
  };

  const handleNodeRequest = async (request: NodeLikeRequest): Promise<SerializedResponse> => {
    try {
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
    } catch (error) {
      return serializeErrorResponse(error, config.exposeUpstreamErrorDetails === true);
    }
  };

  const createExpressMiddleware = () => {
    return async (
      req: NodeLikeRequest,
      res: NodeLikeResponse,
      next?: (error?: unknown) => void,
    ): Promise<void> => {
      try {
        const serialized = await handleNodeRequest(req);
        sendSerializedNodeResponse(res, serialized, req.method?.toUpperCase() === "HEAD");
      } catch (error) {
        if (next) {
          next(error);
          return;
        }
        sendSerializedNodeResponse(
          res,
          serializeErrorResponse(error, config.exposeUpstreamErrorDetails === true),
          req.method?.toUpperCase() === "HEAD",
        );
      }
    };
  };

  const createFastifyHandler = () => {
    return async (request: NodeLikeRequest, reply: NodeLikeResponse): Promise<void> => {
      const serialized = await handleNodeRequest(request);
      sendSerializedNodeResponse(reply, serialized, request.method?.toUpperCase() === "HEAD");
    };
  };

  const createNestHandler = () => {
    return async (request: NodeLikeRequest, response: NodeLikeResponse): Promise<void> => {
      const serialized = await handleNodeRequest(request);
      sendSerializedNodeResponse(response, serialized, request.method?.toUpperCase() === "HEAD");
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
