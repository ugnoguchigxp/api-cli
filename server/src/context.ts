import type { HeaderContextOptions, RequestContext } from "./types";

type HeaderMap = Headers | Record<string, string | string[] | undefined>;

function getHeaderValue(headers: HeaderMap, headerName: string): string | undefined {
  if (headers instanceof Headers) {
    return headers.get(headerName) ?? undefined;
  }

  const direct =
    headers[headerName] ?? headers[headerName.toLowerCase()] ?? headers[headerName.toUpperCase()];
  if (Array.isArray(direct)) {
    return direct[0];
  }
  return direct;
}

export function createContextFromHeaders(
  headers: HeaderMap,
  options: HeaderContextOptions = {},
): RequestContext {
  const tenantIdHeader = options.tenantIdHeader ?? "x-tenant-id";
  const userIdHeader = options.userIdHeader ?? "x-user-id";
  const requestIdHeader = options.requestIdHeader ?? "x-request-id";

  const tenantId = getHeaderValue(headers, tenantIdHeader);
  const userId = getHeaderValue(headers, userIdHeader);
  const requestId = getHeaderValue(headers, requestIdHeader);

  const context: RequestContext = {};
  if (tenantId !== undefined) {
    context.tenantId = tenantId;
  }
  if (userId !== undefined) {
    context.userId = userId;
  }
  if (requestId !== undefined) {
    context.requestId = requestId;
  }

  if (options.includeRawHeadersInMetadata) {
    context.metadata = {
      headers: headers instanceof Headers ? Object.fromEntries(headers.entries()) : headers,
    };
  }

  return context;
}

export function createContextFromWebRequest(
  request: Request,
  options: HeaderContextOptions = {},
): RequestContext {
  return createContextFromHeaders(request.headers, options);
}

export function createContextFromNodeRequest(
  request: { headers: Record<string, string | string[] | undefined> },
  options: HeaderContextOptions = {},
): RequestContext {
  return createContextFromHeaders(request.headers, options);
}
