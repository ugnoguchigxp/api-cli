import { describe, expect, it, vi } from 'vitest';
import { ApiClient, ApiCliError, ApiCliHttpError } from '../src';

describe('ApiClient', () => {
  it('throws PROVIDER_NOT_FOUND when resolver returns null', async () => {
    const client = new ApiClient({
      providerResolver: () => null,
      fetchImpl: vi.fn() as unknown as typeof fetch
    });

    await expect(
      client.call({
        providerId: 'missing',
        method: 'GET',
        path: '/v1/ping'
      })
    ).rejects.toMatchObject({ code: 'PROVIDER_NOT_FOUND' });
  });

  it('resolves auth header, appends query and sends json body', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      return new Response(
        JSON.stringify({
          url: String(input),
          method: init?.method,
          authorization: new Headers(init?.headers).get('authorization'),
          contentType: new Headers(init?.headers).get('content-type')
        }),
        {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        }
      );
    });

    const client = new ApiClient({
      providerResolver: () => ({
        id: 'p1',
        baseUrl: 'https://api.example.com',
        defaultHeaders: {
          'x-default': '1'
        }
      }),
      authAdapter: {
        resolveAuthHeader: () => ({
          headerName: 'authorization',
          headerValue: 'Bearer token-123'
        })
      },
      fetchImpl: fetchMock as unknown as typeof fetch
    });

    const res = await client.call<{
      url: string;
      method: string;
      authorization: string;
      contentType: string;
    }>({
      providerId: 'p1',
      method: 'POST',
      path: 'v1/chat',
      query: { page: 2, tags: ['a', 'b'] },
      body: { prompt: 'hi' }
    });

    expect(res.status).toBe(200);
    expect(res.data.url).toContain('/v1/chat?page=2&tags=a&tags=b');
    expect(res.data.method).toBe('POST');
    expect(res.data.authorization).toBe('Bearer token-123');
    expect(res.data.contentType).toContain('application/json');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns text in auto mode for non-json response', async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: 'p1', baseUrl: 'https://api.example.com' }),
      fetchImpl: vi.fn(async () => new Response('ok', { status: 200 })) as unknown as typeof fetch
    });

    const res = await client.call<string>({
      providerId: 'p1',
      method: 'GET',
      path: '/status'
    });

    expect(res.data).toBe('ok');
  });

  it('throws ApiCliHttpError on non-2xx response', async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: 'p1', baseUrl: 'https://api.example.com' }),
      fetchImpl: vi.fn(async () => {
        return new Response('bad-request', { status: 400, headers: { 'x-id': 'e1' } });
      }) as unknown as typeof fetch
    });

    await expect(
      client.call({
        providerId: 'p1',
        method: 'GET',
        path: '/v1/fail'
      })
    ).rejects.toBeInstanceOf(ApiCliHttpError);

    try {
      await client.call({ providerId: 'p1', method: 'GET', path: '/v1/fail' });
    } catch (error) {
      expect(error).toBeInstanceOf(ApiCliHttpError);
      const httpError = error as ApiCliHttpError;
      expect(httpError.status).toBe(400);
      expect(httpError.responseText).toBe('bad-request');
      expect(httpError.code).toBe('HTTP_ERROR');
    }
  });

  it('throws TIMEOUT when fetch is aborted', async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal as AbortSignal | undefined;
        signal?.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'));
        });
      });
    });

    const client = new ApiClient({
      providerResolver: () => ({ id: 'p1', baseUrl: 'https://api.example.com' }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      defaultTimeoutMs: 5
    });

    await expect(
      client.call({
        providerId: 'p1',
        method: 'GET',
        path: '/slow'
      })
    ).rejects.toMatchObject({ code: 'TIMEOUT' } satisfies Partial<ApiCliError>);
  });
});
