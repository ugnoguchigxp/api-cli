import { ApiCliError, ApiCliHttpError } from './errors';
import type {
  ApiCallRequest,
  ApiCallResponse,
  ApiClientOptions,
  QueryValue,
  ResponseParseMode
} from './types';

function isBodyInitLike(value: unknown): value is BodyInit {
  if (typeof value === 'string') {
    return true;
  }

  if (value instanceof URLSearchParams) {
    return true;
  }

  if (typeof FormData !== 'undefined' && value instanceof FormData) {
    return true;
  }

  if (typeof Blob !== 'undefined' && value instanceof Blob) {
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

function appendQueryParams(url: URL, query?: Record<string, QueryValue | undefined>): void {
  if (!query) {
    return;
  }

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        url.searchParams.append(key, String(item));
      }
    } else {
      url.searchParams.set(key, String(value));
    }
  }
}

function normalizeUrl(baseUrl: string, path: string): URL {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return new URL(`${baseUrl.replace(/\/$/, '')}${normalizedPath}`);
}

async function parseResponse(response: Response, mode: ResponseParseMode): Promise<unknown> {
  if (mode === 'raw') {
    return response;
  }

  if (mode === 'text') {
    return response.text();
  }

  if (mode === 'json') {
    try {
      return await response.json();
    } catch (error) {
      throw new ApiCliError('INVALID_RESPONSE', 'Failed to parse JSON response', undefined, {
        cause: error
      });
    }
  }

  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (contentType.includes('application/json')) {
    try {
      return await response.json();
    } catch {
      return response.text();
    }
  }

  return response.text();
}

export class ApiClient {
  private readonly providerResolver: ApiClientOptions['providerResolver'];
  private readonly authAdapter?: ApiClientOptions['authAdapter'];
  private readonly fetchImpl: typeof fetch;
  private readonly defaultTimeoutMs: number;

  constructor(options: ApiClientOptions) {
    this.providerResolver = options.providerResolver;
    this.authAdapter = options.authAdapter;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 10_000;
  }

  async call<T = unknown>(request: ApiCallRequest): Promise<ApiCallResponse<T>> {
    const provider = await this.providerResolver(request.providerId, request.context);
    if (!provider) {
      throw new ApiCliError('PROVIDER_NOT_FOUND', `Provider not found: ${request.providerId}`);
    }

    const url = normalizeUrl(provider.baseUrl, request.path);
    appendQueryParams(url, request.query);

    const headers = new Headers(provider.defaultHeaders ?? {});
    for (const [key, value] of Object.entries(request.headers ?? {})) {
      headers.set(key, value);
    }

    if (this.authAdapter) {
      const resolved = await this.authAdapter.resolveAuthHeader(
        request.context !== undefined
          ? { provider, context: request.context }
          : { provider }
      );
      if (resolved) {
        headers.set(resolved.headerName, resolved.headerValue);
      }
    }

    let body: BodyInit | undefined;
    if (request.body !== undefined) {
      if (isBodyInitLike(request.body)) {
        body = request.body;
      } else {
        if (!headers.has('content-type')) {
          headers.set('content-type', 'application/json');
        }
        body = JSON.stringify(request.body);
      }
    }

    const timeoutMs = request.timeoutMs ?? provider.timeoutMs ?? this.defaultTimeoutMs;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await this.fetchImpl(url, {
        method: request.method,
        headers,
        body: body ?? null,
        signal: controller.signal
      });

      const raw = response.clone();
      if (!response.ok) {
        const responseText = await response.text();
        throw new ApiCliHttpError({
          status: response.status,
          message: `HTTP request failed (${response.status}) for ${request.method} ${url.pathname}`,
          responseText,
          responseHeaders: headersToObject(response.headers),
          details: {
            providerId: request.providerId,
            url: url.toString(),
            method: request.method
          }
        });
      }

      const mode = request.parseAs ?? 'auto';
      const data = (await parseResponse(response, mode)) as T;
      return {
        status: response.status,
        headers: headersToObject(response.headers),
        data,
        raw
      };
    } catch (error) {
      if (error instanceof ApiCliError) {
        throw error;
      }

      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new ApiCliError('TIMEOUT', `Request timed out after ${timeoutMs}ms`, {
          providerId: request.providerId,
          path: request.path,
          timeoutMs
        });
      }

      throw new ApiCliError('FETCH_ERROR', 'Network request failed', undefined, {
        cause: error instanceof Error ? error : undefined
      });
    } finally {
      clearTimeout(timeout);
    }
  }
}
