import { describe, expect, it, vi } from "vitest";
import { type ApiCliError, ApiClient, ApiCliHttpError } from "../src";

describe("ApiClient", () => {
  it("throws PROVIDER_NOT_FOUND when resolver returns null", async () => {
    const client = new ApiClient({
      providerResolver: () => null,
      fetchImpl: vi.fn() as unknown as typeof fetch,
    });

    await expect(
      client.call({
        providerId: "missing",
        method: "GET",
        path: "/v1/ping",
      }),
    ).rejects.toMatchObject({ code: "PROVIDER_NOT_FOUND" });
  });

  it("resolves auth header, appends query and sends json body", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      return new Response(
        JSON.stringify({
          url: String(input),
          method: init?.method,
          authorization: new Headers(init?.headers).get("authorization"),
          contentType: new Headers(init?.headers).get("content-type"),
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        },
      );
    });

    const client = new ApiClient({
      providerResolver: () => ({
        id: "p1",
        baseUrl: "https://api.example.com",
        defaultHeaders: {
          "x-default": "1",
        },
      }),
      authAdapter: {
        resolveAuthHeader: () => ({
          headerName: "authorization",
          headerValue: "Bearer token-123",
        }),
      },
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const res = await client.call<{
      url: string;
      method: string;
      authorization: string;
      contentType: string;
    }>({
      providerId: "p1",
      method: "POST",
      path: "v1/chat",
      query: { page: 2, tags: ["a", "b"] },
      body: { prompt: "hi" },
    });

    expect(res.status).toBe(200);
    expect(res.data.url).toContain("/v1/chat?page=2&tags=a&tags=b");
    expect(res.data.method).toBe("POST");
    expect(res.data.authorization).toBe("Bearer token-123");
    expect(res.data.contentType).toContain("application/json");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("returns text in auto mode for non-json response", async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => new Response("ok", { status: 200 })) as unknown as typeof fetch,
    });

    const res = await client.call<string>({
      providerId: "p1",
      method: "GET",
      path: "/status",
    });

    expect(res.data).toBe("ok");
  });

  it("throws ApiCliHttpError on non-2xx response", async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => {
        return new Response("bad-request", { status: 400, headers: { "x-id": "e1" } });
      }) as unknown as typeof fetch,
    });

    await expect(
      client.call({
        providerId: "p1",
        method: "GET",
        path: "/v1/fail",
      }),
    ).rejects.toBeInstanceOf(ApiCliHttpError);

    try {
      await client.call({ providerId: "p1", method: "GET", path: "/v1/fail" });
    } catch (error) {
      expect(error).toBeInstanceOf(ApiCliHttpError);
      const httpError = error as ApiCliHttpError;
      expect(httpError.status).toBe(400);
      expect(httpError.responseText).toBe("bad-request");
      expect(httpError.code).toBe("HTTP_ERROR");
    }
  });

  it("throws TIMEOUT when fetch is aborted", async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal as AbortSignal | undefined;
        signal?.addEventListener("abort", () => {
          reject(new DOMException("Aborted", "AbortError"));
        });
      });
    });

    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      defaultTimeoutMs: 5,
    });

    await expect(
      client.call({
        providerId: "p1",
        method: "GET",
        path: "/slow",
      }),
    ).rejects.toMatchObject({ code: "TIMEOUT" } satisfies Partial<ApiCliError>);
  });

  it("throws INVALID_RESPONSE for forced json parse failures", async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => {
        return new Response("not-json", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      }) as unknown as typeof fetch,
    });

    await expect(
      client.call({
        providerId: "p1",
        method: "GET",
        path: "/v1/json",
        parseAs: "json",
      }),
    ).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
  });

  it("throws FETCH_ERROR for generic network failures", async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => {
        throw new Error("network down");
      }) as unknown as typeof fetch,
    });

    await expect(
      client.call({
        providerId: "p1",
        method: "GET",
        path: "/v1/fetch-fail",
      }),
    ).rejects.toMatchObject({ code: "FETCH_ERROR" });
  });

  it("supports raw response parsing mode", async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => {
        return new Response("raw-body", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      }) as unknown as typeof fetch,
    });

    const result = await client.call<Response>({
      providerId: "p1",
      method: "GET",
      path: "/v1/raw",
      parseAs: "raw",
    });

    expect(result.data).toBeInstanceOf(Response);
    expect(await result.data.text()).toBe("raw-body");
  });

  it("falls back to the original text for invalid JSON in auto mode", async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => {
        return new Response("{invalid", {
          headers: { "content-type": "application/json" },
        });
      }) as unknown as typeof fetch,
    });

    const result = await client.call<string>({ providerId: "p1", method: "GET", path: "/data" });
    expect(result.data).toBe("{invalid");
  });

  it("recognizes structured JSON media types in auto mode", async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(
        async () =>
          new Response('{"ok":true}', {
            headers: { "content-type": "application/problem+json; charset=utf-8" },
          }),
      ) as unknown as typeof fetch,
    });

    await expect(
      client.call({ providerId: "p1", method: "GET", path: "/data" }),
    ).resolves.toMatchObject({ data: { ok: true } });
  });

  it("enforces request, response, and error body limits", async () => {
    const responseClient = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => new Response("12345")) as unknown as typeof fetch,
      limits: { maxRequestBytes: 4, maxResponseBytes: 4, maxErrorBytes: 3 },
    });

    await expect(
      responseClient.call({ providerId: "p1", method: "POST", path: "/x", body: "12345" }),
    ).rejects.toMatchObject({ code: "REQUEST_TOO_LARGE" });
    await expect(
      responseClient.call({ providerId: "p1", method: "GET", path: "/x" }),
    ).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });

    const errorClient = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(
        async () => new Response("1234", { status: 500 }),
      ) as unknown as typeof fetch,
      limits: { maxErrorBytes: 3 },
    });
    await expect(
      errorClient.call({ providerId: "p1", method: "GET", path: "/x" }),
    ).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });
  });

  it("keeps requests inside the provider base path and disables redirects", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe("https://api.example.com/allowed/v1/items");
      expect(init?.redirect).toBe("manual");
      return new Response("ok");
    });
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com/allowed" }),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    await client.call({ providerId: "p1", method: "GET", path: "/v1/items" });
    await expect(
      client.call({ providerId: "p1", method: "GET", path: "/../admin" }),
    ).rejects.toMatchObject({ code: "BLOCKED_URL" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("requires HTTPS unless loopback HTTP is explicitly enabled", async () => {
    const blocked = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "http://api.example.com" }),
      fetchImpl: vi.fn() as unknown as typeof fetch,
    });
    await expect(
      blocked.call({ providerId: "p1", method: "GET", path: "/x" }),
    ).rejects.toMatchObject({ code: "BLOCKED_URL" });

    const ambiguousLocalhost = new ApiClient({
      providerResolver: () => ({
        id: "p1",
        baseUrl: "http://localhost:3000",
        allowInsecureHttp: true,
        allowPrivateNetwork: true,
      }),
      fetchImpl: vi.fn() as unknown as typeof fetch,
    });
    await expect(
      ambiguousLocalhost.call({ providerId: "p1", method: "GET", path: "/x" }),
    ).rejects.toMatchObject({ code: "BLOCKED_URL" });

    const allowed = new ApiClient({
      providerResolver: () => ({
        id: "p1",
        baseUrl: "http://127.0.0.1:3000",
        allowInsecureHttp: true,
        allowPrivateNetwork: true,
      }),
      fetchImpl: vi.fn(async () => new Response("ok")) as unknown as typeof fetch,
    });
    await expect(
      allowed.call({ providerId: "p1", method: "GET", path: "/x" }),
    ).resolves.toMatchObject({ data: "ok" });
  });

  it("blocks private and special-purpose targets unless explicitly allowed", async () => {
    const fetchMock = vi.fn(async () => new Response("ok"));
    const blocked = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://127.0.0.1" }),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    await expect(
      blocked.call({ providerId: "p1", method: "GET", path: "/x" }),
    ).rejects.toMatchObject({ code: "BLOCKED_URL" });

    const allowed = new ApiClient({
      providerResolver: () => ({
        id: "p1",
        baseUrl: "https://10.0.0.1",
        allowPrivateNetwork: true,
      }),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    await expect(
      allowed.call({ providerId: "p1", method: "GET", path: "/x" }),
    ).resolves.toMatchObject({ data: "ok" });
  });

  it("rejects unsafe methods, bodies, headers, and timeout values before fetch", async () => {
    const fetchMock = vi.fn(async () => new Response("ok"));
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    await expect(
      client.call({ providerId: "p1", method: "GET", path: "/x", body: "no" }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      client.call({ providerId: "p1", method: "POST", path: "/x", headers: { host: "evil" } }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      client.call({ providerId: "p1", method: "GET", path: "/x", timeoutMs: 0 }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects non-serializable bodies and excessive limits before fetch", async () => {
    const fetchMock = vi.fn(async () => new Response("ok"));
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    const circular: Record<string, unknown> = {};
    circular.self = circular;

    await expect(
      client.call({ providerId: "p1", method: "POST", path: "/x", body: circular }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      client.call({ providerId: "p1", method: "POST", path: "/x", body: () => undefined }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(
      () =>
        new ApiClient({
          providerResolver: () => null,
          defaultTimeoutMs: 300_001,
        }),
    ).toThrow(/no greater than/i);
    expect(
      () =>
        new ApiClient({
          providerResolver: () => null,
          limits: { maxResponseBytes: 16 * 1024 * 1024 + 1 },
        }),
    ).toThrow(/no greater than/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("handles bodyless success responses without constructing an invalid Response", async () => {
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => new Response(null, { status: 204 })) as unknown as typeof fetch,
    });

    const result = await client.call<Response>({
      providerId: "p1",
      method: "GET",
      path: "/empty",
      parseAs: "raw",
    });
    expect(result.status).toBe(204);
    expect(result.raw.status).toBe(204);
    expect((await result.data.arrayBuffer()).byteLength).toBe(0);
  });

  it("keeps the size error when stream cancellation fails", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
      },
      cancel() {
        throw new Error("cancel failed");
      },
    });
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn(async () => new Response(stream)) as unknown as typeof fetch,
      limits: { maxResponseBytes: 2 },
    });

    await expect(
      client.call({ providerId: "p1", method: "GET", path: "/large" }),
    ).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });
  });

  it("normalizes runtime method casing and bounds the final URL", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.method).toBe("GET");
      return new Response("ok");
    });
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    await client.call({ providerId: "p1", method: "get" as never, path: "/x" });
    await expect(
      client.call({
        providerId: "p1",
        method: "GET",
        path: "/x",
        query: { value: ["x".repeat(6_000), "y".repeat(6_000), "z".repeat(6_000)] },
      }),
    ).rejects.toMatchObject({ code: "BLOCKED_URL" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("bounds identifiers, query entries, and request headers before fetch", async () => {
    const fetchMock = vi.fn(async () => new Response("ok"));
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    await expect(
      client.call({ providerId: " p1", method: "GET", path: "/x" }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      client.call({
        providerId: "p1",
        method: "GET",
        path: "/x",
        query: { item: Array.from({ length: 257 }, (_, index) => index) },
      }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      client.call({
        providerId: "p1",
        method: "GET",
        path: "/x",
        headers: Object.fromEntries(
          Array.from({ length: 129 }, (_, index) => [`x-header-${index}`, "value"]),
        ),
      }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("blocks additional reserved IP ranges and encoded controls", async () => {
    const blockedHosts = [
      "192.0.2.1",
      "198.51.100.1",
      "203.0.113.1",
      "[::ffff:127.0.0.1]",
      "[2001:db8::1]",
    ];
    for (const hostname of blockedHosts) {
      const client = new ApiClient({
        providerResolver: () => ({ id: "p1", baseUrl: `https://${hostname}` }),
        fetchImpl: vi.fn() as unknown as typeof fetch,
      });
      await expect(
        client.call({ providerId: "p1", method: "GET", path: "/x" }),
      ).rejects.toMatchObject({ code: "BLOCKED_URL" });
    }

    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: vi.fn() as unknown as typeof fetch,
    });
    await expect(
      client.call({ providerId: "p1", method: "GET", path: "/x/%00" }),
    ).rejects.toMatchObject({ code: "BLOCKED_URL" });
  });

  it("classifies a non-DOM abort as TIMEOUT after the deadline", async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("socket aborted")));
      });
    });
    const client = new ApiClient({
      providerResolver: () => ({ id: "p1", baseUrl: "https://api.example.com" }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      defaultTimeoutMs: 5,
    });

    await expect(
      client.call({ providerId: "p1", method: "GET", path: "/slow" }),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
  });
});
