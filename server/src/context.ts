import type { HeaderContextOptions, RequestContext } from "./types";

type HeaderMap = Headers | Record<string, string | string[] | undefined>;

function getHeaderValue(headers: HeaderMap, headerName: string): string | undefined {
  if (headers instanceof Headers) {
    return headers.get(headerName) ?? undefined;
  }

  const normalized = headerName.toLowerCase();
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() !== normalized) {
      continue;
    }
    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }
  return undefined;
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
      headers:
        headers instanceof Headers
          ? Object.fromEntries(headers.entries())
          : Object.fromEntries(
              Object.entries(headers).map(([name, value]) => [
                name,
                Array.isArray(value) ? [...value] : value,
              ]),
            ),
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
