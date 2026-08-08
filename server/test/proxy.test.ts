import { describe, expect, it, vi } from "vitest";
import {
  ApiCliError,
  type ApiProxyServerConfig,
  createApiProxyServer as createStrictApiProxyServer,
  type NodeLikeRequest,
  type NodeLikeResponse,
} from "../src";

const ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as const;

function createApiProxyServer(config: ApiProxyServerConfig) {
  return createStrictApiProxyServer({
    ...config,
    allowedMethods: config.allowedMethods ?? [...ALL_METHODS],
    allowedPathPrefixes: config.allowedPathPrefixes ?? ["/"],
  });
}

function serializedText(body: string | Uint8Array): string {
  return typeof body === "string" ? body : new TextDecoder().decode(body);
}

describe("createApiProxyServer", () => {
  it("proxies web request with static bearer auth", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      return new Response(
        JSON.stringify({
          url: String(input),
          method: init?.method,
          auth: new Headers(init?.headers).get("authorization"),
          contentType: new Headers(init?.headers).get("content-type"),
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    });

    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      auth: {
        mode: "static-bearer",
        token: "token-1",
      },
      routePrefix: "/apicli",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const request = new Request("https://app.local/apicli/billing/v1/items?page=1&tag=a&tag=b", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hello: "world" }),
    });

    const response = await proxy.handleWebRequest(request);
    const body = (await response.json()) as {
      url: string;
      method: string;
      auth: string;
      contentType: string;
    };

    expect(response.status).toBe(200);
    expect(body.url).toContain("https://billing.example.com/v1/items?page=1&tag=a&tag=b");
    expect(body.method).toBe("POST");
    expect(body.auth).toBe("Bearer token-1");
    expect(body.contentType).toBe("application/json");
  });

  it("supports forward-header auth mode", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      return new Response(
        JSON.stringify({
          auth: new Headers(init?.headers).get("authorization"),
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    });

    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      auth: {
        mode: "forward-header",
        sourceHeaderName: "x-access-token",
        targetHeaderName: "authorization",
        passthrough: false,
        scheme: "Bearer",
      },
      routePrefix: "/apicli",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const request = new Request("https://app.local/apicli/billing/v1/items", {
      method: "GET",
      headers: {
        "x-access-token": "abc123",
      },
    });

    const response = await proxy.handleWebRequest(request);
    const body = (await response.json()) as { auth: string };

    expect(response.status).toBe(200);
    expect(body.auth).toBe("Bearer abc123");
  });

  it("returns 400 when provider id is missing", async () => {
    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      routePrefix: "/apicli",
    });

    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/", { method: "GET" }),
    );
    const body = (await response.json()) as { ok: boolean; error: { code: string } };

    expect(response.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe("BAD_REQUEST");
  });

  it("does not serve web requests outside the configured route prefix", async () => {
    const fetchMock = vi.fn(async () => new Response("unexpected"));
    const proxy = createApiProxyServer({
      providers: {
        billing: { id: "billing", baseUrl: "https://billing.example.com" },
      },
      routePrefix: "/apicli",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const response = await proxy.handleWebRequest(
      new Request("https://app.local/not-apicli/billing/v1/items"),
    );
    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns 405 for disallowed method", async () => {
    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      allowedMethods: ["GET"],
      routePrefix: "/apicli",
    });

    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/items", { method: "POST", body: "{}" }),
    );
    const body = (await response.json()) as { error: { code: string } };

    expect(response.status).toBe(405);
    expect(body.error.code).toBe("METHOD_NOT_ALLOWED");
  });

  it("express middleware can run with minimal glue code", async () => {
    const fetchMock = vi.fn(async () => {
      return new Response("pong", {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    });

    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const middleware = proxy.createExpressMiddleware();

    const req: NodeLikeRequest = {
      method: "GET",
      path: "/billing/v1/ping",
      query: { q: "x" },
      headers: {},
    };

    let sentBody: unknown;
    let statusCode = 0;
    const res: NodeLikeResponse = {
      status(code) {
        statusCode = code;
        return this;
      },
      send(body) {
        sentBody = body;
      },
      setHeader: () => {
        // noop
      },
    };

    await middleware(req, res);

    expect(statusCode).toBe(200);
    expect(sentBody).toBe("pong");
  });

  it("next route handlers are generated as one-liner handlers", async () => {
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      routePrefix: "/api/apicli",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const handlers = proxy.createNextRouteHandlers();
    const response = await handlers.GET(
      new Request("https://app.local/api/apicli/billing/v1/ping"),
    );
    const body = (await response.json()) as { ok: boolean };

    expect(response.status).toBe(200);
    expect(body.ok).toBe(true);
  });

  it("supports provider/path through query params", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      return new Response(
        JSON.stringify({
          url: String(input),
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });

    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      routePrefix: "/apicli",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli?provider=billing&path=/v2/items&active=true"),
    );
    const body = (await response.json()) as { url: string };

    expect(response.status).toBe(200);
    expect(body.url).toContain("https://billing.example.com/v2/items?active=true");
  });

  it("returns 400 when allowTargetPath rejects route", async () => {
    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      allowTargetPath: () => false,
      routePrefix: "/apicli",
    });

    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/secret", { method: "GET" }),
    );
    const body = (await response.json()) as { error: { code: string } };

    expect(response.status).toBe(400);
    expect(body.error.code).toBe("BAD_REQUEST");
  });

  it("maps upstream HTTP error to same status", async () => {
    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      routePrefix: "/apicli",
      fetchImpl: vi.fn(async () => {
        return new Response("unauthorized", {
          status: 401,
          headers: { "content-type": "text/plain" },
        });
      }) as unknown as typeof fetch,
    });

    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/resource", { method: "GET" }),
    );
    const body = (await response.json()) as {
      error: { code: string; details: { upstreamStatus: number } };
    };

    expect(response.status).toBe(401);
    expect(body.error.code).toBe("HTTP_ERROR");
    expect(body.error.details.upstreamStatus).toBe(401);
  });

  it("hono handler returns web response directly", async () => {
    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      routePrefix: "/apicli",
      fetchImpl: vi.fn(async () => {
        return new Response("hono-ok", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      }) as unknown as typeof fetch,
    });

    const handler = proxy.createHonoHandler();
    const response = await handler({
      req: {
        raw: new Request("https://app.local/apicli/billing/v1/ping"),
      },
    });

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("hono-ok");
  });

  it("node handler parses JSON string body when content-type is JSON", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      return new Response(
        JSON.stringify({
          bodyType: typeof init?.body,
          body: init?.body,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });

    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const response = await proxy.handleNodeRequest({
      method: "POST",
      path: "/billing/v1/ping",
      headers: {
        "content-type": "application/json",
      },
      body: '{"x":1}',
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(serializedText(response.body))).toEqual({
      bodyType: "string",
      body: JSON.stringify({ x: 1 }),
    });
  });

  it("fastify and nest handlers can write response with same adapter", async () => {
    const proxy = createApiProxyServer({
      providers: {
        billing: {
          id: "billing",
          baseUrl: "https://billing.example.com",
        },
      },
      fetchImpl: vi.fn(async () => {
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }) as unknown as typeof fetch,
    });

    const request: NodeLikeRequest = {
      method: "GET",
      path: "/billing/v1/ping",
      headers: {},
    };

    const makeResponse = () => {
      let statusCode = 0;
      let body: unknown;
      const response: NodeLikeResponse = {
        status(code) {
          statusCode = code;
          return this;
        },
        json(payload) {
          body = payload;
        },
        setHeader: () => {
          // noop
        },
      };

      return { response, getStatus: () => statusCode, getBody: () => body };
    };

    const fastify = makeResponse();
    const nest = makeResponse();

    await proxy.createFastifyHandler()(request, fastify.response);
    await proxy.createNestHandler()(request, nest.response);

    expect(fastify.getStatus()).toBe(200);
    expect(nest.getStatus()).toBe(200);
    expect(fastify.getBody()).toEqual({ ok: true });
    expect(nest.getBody()).toEqual({ ok: true });
  });

  it("requires an explicit path policy", () => {
    expect(() =>
      createStrictApiProxyServer({
        providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      }),
    ).toThrow(/path policy/i);
  });

  it("rejects unsafe forwarded transport headers", () => {
    expect(() =>
      createStrictApiProxyServer({
        providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
        allowedPathPrefixes: ["/v1"],
        forwardHeaders: ["host"],
      }),
    ).toThrow(/forbidden forwarded header/i);
  });

  it("allows only read methods by default", async () => {
    const proxy = createStrictApiProxyServer({
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedPathPrefixes: ["/v1"],
    });
    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/items", { method: "POST", body: "{}" }),
    );
    expect(response.status).toBe(405);
  });

  it("bounds inbound web request bodies", async () => {
    const proxy = createStrictApiProxyServer({
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedMethods: ["POST"],
      allowedPathPrefixes: ["/v1"],
      limits: { maxRequestBytes: 3 },
    });
    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/items", {
        method: "POST",
        body: "1234",
      }),
    );
    expect(response.status).toBe(413);
  });

  it("redacts upstream bodies and headers by default", async () => {
    const proxy = createStrictApiProxyServer({
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedPathPrefixes: ["/v1"],
      fetchImpl: vi.fn(async () => {
        return new Response("secret-detail", {
          status: 500,
          headers: { "x-internal": "secret" },
        });
      }) as unknown as typeof fetch,
    });
    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/items?secret=top-secret"),
    );
    const body = (await response.json()) as { error: { details: Record<string, unknown> } };
    expect(body.error.details.upstreamStatus).toBe(500);
    expect(body.error.details.upstreamBody).toBeUndefined();
    expect(body.error.details.upstreamHeaders).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain("top-secret");
  });

  it("normalizes unexpected adapter errors without exposing their messages", async () => {
    const proxy = createStrictApiProxyServer({
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedPathPrefixes: ["/v1"],
      contextResolver: () => {
        throw new Error("database password leaked");
      },
    });
    const web = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/items"),
    );
    expect(web.status).toBe(500);
    expect(await web.text()).not.toContain("database password leaked");

    const node = await proxy.handleNodeRequest({
      method: "GET",
      url: "/apicli/billing/v1/items",
    });
    expect(node.status).toBe(500);
    expect(serializedText(node.body)).not.toContain("database password leaked");
  });

  it("rejects malformed JSON instead of forwarding it as text", async () => {
    const fetchMock = vi.fn(async () => new Response("unexpected"));
    const proxy = createStrictApiProxyServer({
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedMethods: ["POST"],
      allowedPathPrefixes: ["/v1"],
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const web = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/items", {
        method: "POST",
        headers: { "content-type": "application/problem+json" },
        body: "{invalid",
      }),
    );
    expect(web.status).toBe(400);

    const node = await proxy.handleNodeRequest({
      method: "POST",
      path: "/billing/v1/items",
      headers: { "content-type": "application/json" },
      body: "{invalid",
    });
    expect(node.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("preserves binary request and response bodies without unsafe response headers", async () => {
    const requestBytes = new Uint8Array([0, 255, 1, 128]);
    const responseBytes = new Uint8Array([255, 0, 254, 1]);
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.body).toEqual(requestBytes);
      expect(new Headers(init?.headers).get("content-type")).toBe("application/octet-stream");
      return new Response(responseBytes, {
        headers: {
          "content-type": "application/octet-stream",
          "content-encoding": "gzip",
          "set-cookie": "secret=value",
          "x-upstream-id": "safe",
        },
      });
    });
    const proxy = createStrictApiProxyServer({
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedMethods: ["POST"],
      allowedPathPrefixes: ["/v1"],
      parseAs: "raw",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const response = await proxy.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/binary", {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: requestBytes,
      }),
    );
    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(responseBytes);
    expect(response.headers.get("x-upstream-id")).toBe("safe");
    expect(response.headers.has("set-cookie")).toBe(false);
    expect(response.headers.has("content-encoding")).toBe(false);
    expect(response.headers.has("content-length")).toBe(false);
  });

  it("handles bodyless upstream responses and converts redirects to a gateway error", async () => {
    const noContent = createStrictApiProxyServer({
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedPathPrefixes: ["/v1"],
      parseAs: "raw",
      fetchImpl: vi.fn(async () => new Response(null, { status: 204 })) as unknown as typeof fetch,
    });
    const empty = await noContent.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/empty"),
    );
    expect(empty.status).toBe(204);
    expect((await empty.arrayBuffer()).byteLength).toBe(0);

    const redirect = createStrictApiProxyServer({
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedPathPrefixes: ["/v1"],
      fetchImpl: vi.fn(async () => new Response(null, { status: 304 })) as unknown as typeof fetch,
    });
    const failed = await redirect.handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/cache"),
    );
    expect(failed.status).toBe(502);
    await expect(failed.json()).resolves.toMatchObject({ error: { code: "HTTP_ERROR" } });
  });

  it("redacts typed error details unless explicit diagnostics are enabled", async () => {
    const makeProxy = (exposeUpstreamErrorDetails: boolean) =>
      createStrictApiProxyServer({
        providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
        allowedPathPrefixes: ["/v1"],
        exposeUpstreamErrorDetails,
        contextResolver: () => {
          throw new ApiCliError("FETCH_ERROR", "adapter failed", { secret: "do-not-expose" });
        },
      });

    const redacted = await makeProxy(false).handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/items"),
    );
    expect(await redacted.text()).not.toContain("do-not-expose");

    const diagnostic = await makeProxy(true).handleWebRequest(
      new Request("https://app.local/apicli/billing/v1/items"),
    );
    expect(await diagnostic.text()).toContain("do-not-expose");
  });

  it("validates methods, paths, header lists, query keys, and auth at startup", () => {
    const base = {
      providers: { billing: { id: "billing", baseUrl: "https://billing.example.com" } },
      allowedPathPrefixes: ["/v1"],
    };
    expect(() => createStrictApiProxyServer({ ...base, allowedMethods: [] })).toThrow(
      /cannot be empty/i,
    );
    expect(() =>
      createStrictApiProxyServer({ ...base, allowedPathPrefixes: ["/%2e%2e/secret"] }),
    ).toThrow(/invalid allowed path prefix/i);
    expect(() => createStrictApiProxyServer({ ...base, forwardHeaders: ["x-id", "X-ID"] })).toThrow(
      /duplicate forwarded header/i,
    );
    expect(() => createStrictApiProxyServer({ ...base, providerQueryParam: "path" })).toThrow(
      /non-empty and distinct/i,
    );
    expect(() =>
      createStrictApiProxyServer({
        ...base,
        auth: { mode: "static-bearer", token: "" },
      }),
    ).toThrow(/cannot be empty/i);
  });
});
