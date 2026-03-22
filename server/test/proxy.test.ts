import { describe, expect, it, vi } from "vitest";
import { createApiProxyServer, type NodeLikeRequest, type NodeLikeResponse } from "../src";

describe("createApiProxyServer", () => {
  it("proxies web request with static bearer auth", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      return new Response(
        JSON.stringify({
          url: String(input),
          method: init?.method,
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
    };

    expect(response.status).toBe(200);
    expect(body.url).toContain("https://billing.example.com/v1/items?page=1&tag=a&tag=b");
    expect(body.method).toBe("POST");
    expect(body.auth).toBe("Bearer token-1");
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
    expect(JSON.parse(response.body)).toEqual({
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
});
