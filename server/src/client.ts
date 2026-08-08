import { isIP } from "node:net";
import { ApiCliError, ApiCliHttpError } from "./errors";
import { isPrivateOrSpecialAddress, networkPolicyFetch } from "./network";
import type {
  ApiCallRequest,
  ApiCallResponse,
  ApiClientOptions,
  QueryValue,
  ResponseParseMode,
} from "./types";

const DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_MAX_ERROR_BYTES = 64 * 1024;
const MAX_BODY_BYTES = 16 * 1024 * 1024;
const MAX_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_URL_LENGTH = 16 * 1024;
const MAX_QUERY_ENTRIES = 256;
const MAX_QUERY_KEY_LENGTH = 256;
const MAX_QUERY_VALUE_LENGTH = 8 * 1024;
const MAX_REQUEST_HEADERS = 128;
const MAX_HEADER_NAME_LENGTH = 256;
const MAX_HEADER_VALUE_LENGTH = 64 * 1024;
const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);
const FORBIDDEN_REQUEST_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authorization",
  "proxy-authenticate",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function positiveLimit(
  value: number | undefined,
  fallback: number,
  name: string,
  maximum: number,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0 || resolved > maximum) {
    throw new ApiCliError(
      "BAD_REQUEST",
      `${name} must be a positive safe integer no greater than ${maximum}`,
    );
  }
  return resolved;
}

function isBodyInitLike(value: unknown): value is BodyInit {
  if (typeof value === "string") {
    return true;
  }

  if (value instanceof URLSearchParams) {
    return true;
  }

  if (typeof FormData !== "undefined" && value instanceof FormData) {
    return true;
  }

  if (typeof Blob !== "undefined" && value instanceof Blob) {
    return true;
  }

  if (value instanceof ArrayBuffer) {
    return true;
  }

  return ArrayBuffer.isView(value);
}

function headersToObject(headers: Headers): Record<string, string> {
  return Object.fromEntries(headers.entries());
}

function validateRequestHeaders(headers: Headers): void {
  const entries = Array.from(headers.entries());
  if (entries.length > MAX_REQUEST_HEADERS) {
    throw new ApiCliError(
      "BAD_REQUEST",
      `Request headers cannot contain more than ${MAX_REQUEST_HEADERS} entries`,
    );
  }
  for (const [name, value] of entries) {
    if (name.length > MAX_HEADER_NAME_LENGTH || value.length > MAX_HEADER_VALUE_LENGTH) {
      throw new ApiCliError("BAD_REQUEST", "Request header name or value exceeds its size limit");
    }
    if (FORBIDDEN_REQUEST_HEADERS.has(name.toLowerCase())) {
      throw new ApiCliError("BAD_REQUEST", `Forbidden request header: ${name}`);
    }
  }
}

function appendQueryParams(url: URL, query?: Record<string, QueryValue | undefined>): void {
  if (!query) {
    return;
  }

  let entryCount = 0;
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) {
      continue;
    }
    if (key.length === 0 || key.length > MAX_QUERY_KEY_LENGTH) {
      throw new ApiCliError("BAD_REQUEST", "Query parameter name exceeds its size limit");
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        const encoded = String(item);
        entryCount += 1;
        if (encoded.length > MAX_QUERY_VALUE_LENGTH || entryCount > MAX_QUERY_ENTRIES) {
          throw new ApiCliError("BAD_REQUEST", "Query parameters exceed their size or count limit");
        }
        url.searchParams.append(key, encoded);
      }
    } else {
      const encoded = String(value);
      entryCount += 1;
      if (encoded.length > MAX_QUERY_VALUE_LENGTH || entryCount > MAX_QUERY_ENTRIES) {
        throw new ApiCliError("BAD_REQUEST", "Query parameters exceed their size or count limit");
      }
      url.searchParams.set(key, encoded);
    }
  }
}

function validateIdentifier(value: string, name: string): void {
  const hasControl = Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
  if (value.length === 0 || value.length > 256 || value.trim() !== value || hasControl) {
    throw new ApiCliError(
      "BAD_REQUEST",
      `${name} must be 1..=256 characters without surrounding whitespace or control characters`,
    );
  }
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "127.0.0.1" || normalized === "[::1]";
}

function isPrivateOrSpecialHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "localhost" || normalized.endsWith(".localhost")) return true;
  return isIP(normalized) !== 0 && isPrivateOrSpecialAddress(normalized);
}

function validatePath(path: string): string {
  const containsControlCharacter = Array.from(path).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
  if (path.includes("\\") || containsControlCharacter) {
    throw new ApiCliError("BLOCKED_URL", "Request path contains forbidden characters");
  }
  if (path.includes("?") || path.includes("#")) {
    throw new ApiCliError("BLOCKED_URL", "Request path cannot contain a query or fragment");
  }
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  for (const rawSegment of normalizedPath.split("/")) {
    let segment: string;
    try {
      segment = decodeURIComponent(rawSegment);
    } catch {
      throw new ApiCliError("BLOCKED_URL", "Request path contains invalid percent encoding");
    }
    const segmentHasControl = Array.from(segment).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f;
    });
    if (
      segment === "." ||
      segment === ".." ||
      segment.includes("/") ||
      segment.includes("\\") ||
      segmentHasControl
    ) {
      throw new ApiCliError("BLOCKED_URL", "Request path cannot contain traversal segments");
    }
  }
  return normalizedPath;
}

function normalizeUrl(
  provider: { baseUrl: string; allowInsecureHttp?: boolean; allowPrivateNetwork?: boolean },
  path: string,
): URL {
  let base: URL;
  try {
    base = new URL(provider.baseUrl);
  } catch (error) {
    throw new ApiCliError("BLOCKED_URL", "Provider base URL is invalid", undefined, {
      cause: error instanceof Error ? error : undefined,
    });
  }
  if (
    !base.hostname ||
    base.username.length > 0 ||
    base.password.length > 0 ||
    base.search.length > 0 ||
    base.hash.length > 0
  ) {
    throw new ApiCliError(
      "BLOCKED_URL",
      "Provider base URL requires a host and cannot contain credentials, query, or fragment",
    );
  }
  if (base.protocol !== "https:") {
    const permittedLoopback =
      base.protocol === "http:" &&
      provider.allowInsecureHttp === true &&
      provider.allowPrivateNetwork === true &&
      isLoopbackHost(base.hostname);
    if (!permittedLoopback) {
      throw new ApiCliError("BLOCKED_URL", "Provider base URL must use HTTPS");
    }
  }
  if (provider.allowPrivateNetwork !== true && isPrivateOrSpecialHost(base.hostname)) {
    throw new ApiCliError(
      "BLOCKED_URL",
      "Provider base URL targets a private or special-purpose network",
    );
  }

  const normalizedPath = validatePath(path);
  const basePrefix = base.pathname.endsWith("/") ? base.pathname : `${base.pathname}/`;
  base.pathname = basePrefix;
  const resolved = new URL(normalizedPath.replace(/^\/+/, ""), base);
  if (resolved.origin !== base.origin || !resolved.pathname.startsWith(basePrefix)) {
    throw new ApiCliError("BLOCKED_URL", "Request path escaped the provider base URL");
  }
  if (resolved.toString().length > MAX_URL_LENGTH) {
    throw new ApiCliError("BLOCKED_URL", `Request URL exceeded ${MAX_URL_LENGTH} characters`);
  }
  return resolved;
}

function bodyForResponse(bytes: Uint8Array, status: number): BodyInit | null {
  if (status === 204 || status === 205 || status === 304) {
    return null;
  }
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function bodyByteLength(body: BodyInit | undefined): number | null {
  if (body === undefined) return 0;
  if (typeof body === "string") return new TextEncoder().encode(body).byteLength;
  if (body instanceof URLSearchParams) return new TextEncoder().encode(body.toString()).byteLength;
  if (typeof Blob !== "undefined" && body instanceof Blob) return body.size;
  if (body instanceof ArrayBuffer) return body.byteLength;
  if (ArrayBuffer.isView(body)) return body.byteLength;
  return null;
}

async function readLimitedBody(response: Response, limit: number): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (Number.isFinite(parsed) && parsed > limit) {
      throw new ApiCliError("RESPONSE_TOO_LARGE", `Response exceeded ${limit} bytes`, { limit });
    }
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
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
          // Preserve the stable size-limit error even if transport cancellation fails.
        }
        throw new ApiCliError("RESPONSE_TOO_LARGE", `Response exceeded ${limit} bytes`, { limit });
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

function parseResponse(bytes: Uint8Array, response: Response, mode: ResponseParseMode): unknown {
  if (mode === "raw") {
    return new Response(bodyForResponse(bytes, response.status), {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  }

  const text = new TextDecoder().decode(bytes);
  if (mode === "text") {
    return text;
  }

  if (mode === "json") {
    try {
      return JSON.parse(text);
    } catch (error) {
      throw new ApiCliError("INVALID_RESPONSE", "Failed to parse JSON response", undefined, {
        cause: error,
      });
    }
  }

  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  const mediaType = contentType.split(";", 1)[0]?.trim() ?? "";
  if (mediaType === "application/json" || mediaType.endsWith("+json")) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  return text;
}

export class ApiClient {
  private readonly providerResolver: ApiClientOptions["providerResolver"];
  private readonly authAdapter?: ApiClientOptions["authAdapter"];
  private readonly fetchImpl: typeof fetch;
  private readonly usesDefaultFetch: boolean;
  private readonly defaultTimeoutMs: number;
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;
  private readonly maxErrorBytes: number;

  constructor(options: ApiClientOptions) {
    this.providerResolver = options.providerResolver;
    this.authAdapter = options.authAdapter;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.usesDefaultFetch = options.fetchImpl === undefined;
    this.defaultTimeoutMs = positiveLimit(
      options.defaultTimeoutMs,
      10_000,
      "defaultTimeoutMs",
      MAX_TIMEOUT_MS,
    );
    this.maxRequestBytes = positiveLimit(
      options.limits?.maxRequestBytes,
      DEFAULT_MAX_REQUEST_BYTES,
      "maxRequestBytes",
      MAX_BODY_BYTES,
    );
    this.maxResponseBytes = positiveLimit(
      options.limits?.maxResponseBytes,
      DEFAULT_MAX_RESPONSE_BYTES,
      "maxResponseBytes",
      MAX_BODY_BYTES,
    );
    this.maxErrorBytes = positiveLimit(
      options.limits?.maxErrorBytes,
      DEFAULT_MAX_ERROR_BYTES,
      "maxErrorBytes",
      MAX_BODY_BYTES,
    );
  }

  async call<T = unknown>(request: ApiCallRequest): Promise<ApiCallResponse<T>> {
    validateIdentifier(request.providerId, "providerId");
    const method = String(request.method).toUpperCase();
    if (!ALLOWED_METHODS.has(method)) {
      throw new ApiCliError("BAD_REQUEST", `Unsupported HTTP method: ${request.method}`);
    }
    if ((method === "GET" || method === "HEAD") && request.body !== undefined) {
      throw new ApiCliError("BAD_REQUEST", `${method} requests cannot include a body`);
    }
    const provider = await this.providerResolver(request.providerId, request.context);
    if (!provider) {
      throw new ApiCliError("PROVIDER_NOT_FOUND", `Provider not found: ${request.providerId}`);
    }

    const url = normalizeUrl(provider, request.path);
    appendQueryParams(url, request.query);
    if (url.toString().length > MAX_URL_LENGTH) {
      throw new ApiCliError("BLOCKED_URL", `Request URL exceeded ${MAX_URL_LENGTH} characters`);
    }

    let headers: Headers;
    try {
      headers = new Headers(provider.defaultHeaders ?? {});
      for (const [key, value] of Object.entries(request.headers ?? {})) {
        headers.set(key, value);
      }

      if (this.authAdapter) {
        const resolved = await this.authAdapter.resolveAuthHeader(
          request.context !== undefined ? { provider, context: request.context } : { provider },
        );
        if (resolved) {
          headers.set(resolved.headerName, resolved.headerValue);
        }
      }
    } catch (error) {
      throw new ApiCliError("BAD_REQUEST", "Request headers are invalid", undefined, {
        cause: error instanceof Error ? error : undefined,
      });
    }
    validateRequestHeaders(headers);

    let body: BodyInit | undefined;
    if (request.body !== undefined) {
      if (isBodyInitLike(request.body)) {
        body = request.body;
      } else {
        if (!headers.has("content-type")) {
          headers.set("content-type", "application/json");
        }
        try {
          const serialized = JSON.stringify(request.body);
          if (serialized === undefined) {
            throw new ApiCliError("BAD_REQUEST", "Request body is not JSON serializable");
          }
          body = serialized;
        } catch (error) {
          if (error instanceof ApiCliError) {
            throw error;
          }
          throw new ApiCliError("BAD_REQUEST", "Request body is not JSON serializable", undefined, {
            cause: error instanceof Error ? error : undefined,
          });
        }
      }
    }

    const requestBytes = bodyByteLength(body);
    if (requestBytes === null) {
      throw new ApiCliError(
        "BAD_REQUEST",
        "This request body type cannot be safely bounded; provide a string, Blob, or byte buffer",
      );
    }
    if (requestBytes > this.maxRequestBytes) {
      throw new ApiCliError("REQUEST_TOO_LARGE", `Request exceeded ${this.maxRequestBytes} bytes`, {
        limit: this.maxRequestBytes,
      });
    }

    const timeoutMs = positiveLimit(
      request.timeoutMs ?? provider.timeoutMs,
      this.defaultTimeoutMs,
      "timeoutMs",
      MAX_TIMEOUT_MS,
    );
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const requestInit: RequestInit = {
        method,
        headers,
        body: body ?? null,
        signal: controller.signal,
        redirect: "manual",
      };
      const response = this.usesDefaultFetch
        ? await networkPolicyFetch(url, requestInit, provider.allowPrivateNetwork === true)
        : await this.fetchImpl(url, requestInit);

      const responseLimit = response.ok ? this.maxResponseBytes : this.maxErrorBytes;
      const responseBytes = await readLimitedBody(response, responseLimit);
      const raw = new Response(bodyForResponse(responseBytes, response.status), {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
      if (!response.ok) {
        const responseText = new TextDecoder().decode(responseBytes);
        throw new ApiCliHttpError({
          status: response.status,
          message: `HTTP request failed (${response.status}) for ${method} ${url.pathname}`,
          responseText,
          responseHeaders: headersToObject(response.headers),
          details: {
            providerId: request.providerId,
            url: url.toString(),
            method,
          },
        });
      }

      const mode = request.parseAs ?? "auto";
      const data = parseResponse(responseBytes, response, mode) as T;
      return {
        status: response.status,
        headers: headersToObject(response.headers),
        data,
        raw,
      };
    } catch (error) {
      if (error instanceof ApiCliError) {
        throw error;
      }

      if (
        controller.signal.aborted ||
        (error instanceof DOMException && error.name === "AbortError")
      ) {
        throw new ApiCliError("TIMEOUT", `Request timed out after ${timeoutMs}ms`, {
          providerId: request.providerId,
          path: request.path,
          timeoutMs,
        });
      }

      throw new ApiCliError("FETCH_ERROR", "Network request failed", undefined, {
        cause: error instanceof Error ? error : undefined,
      });
    } finally {
      clearTimeout(timeout);
    }
  }
}
