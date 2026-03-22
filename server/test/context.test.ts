import { describe, expect, it } from "vitest";
import {
  createContextFromHeaders,
  createContextFromNodeRequest,
  createContextFromWebRequest,
} from "../src";

describe("context helpers", () => {
  it("builds context from node headers", () => {
    const context = createContextFromNodeRequest({
      headers: {
        "x-tenant-id": "tenant-1",
        "x-user-id": "user-1",
        "x-request-id": "req-1",
      },
    });

    expect(context).toEqual({
      tenantId: "tenant-1",
      userId: "user-1",
      requestId: "req-1",
    });
  });

  it("supports custom header names", () => {
    const context = createContextFromHeaders(
      {
        "x-org": "org-1",
        "x-actor": "actor-1",
        "x-correlation-id": "corr-1",
      },
      {
        tenantIdHeader: "x-org",
        userIdHeader: "x-actor",
        requestIdHeader: "x-correlation-id",
      },
    );

    expect(context.tenantId).toBe("org-1");
    expect(context.userId).toBe("actor-1");
    expect(context.requestId).toBe("corr-1");
  });

  it("builds context from web Request headers", () => {
    const request = new Request("https://example.com", {
      headers: {
        "x-tenant-id": "tenant-2",
        "x-user-id": "user-2",
        "x-request-id": "req-2",
      },
    });

    const context = createContextFromWebRequest(request);
    expect(context.tenantId).toBe("tenant-2");
    expect(context.userId).toBe("user-2");
    expect(context.requestId).toBe("req-2");
  });

  it("can include raw headers in metadata", () => {
    const context = createContextFromHeaders(
      {
        "x-tenant-id": "tenant-3",
        "x-user-id": "user-3",
      },
      {
        includeRawHeadersInMetadata: true,
      },
    );

    expect(context.tenantId).toBe("tenant-3");
    expect(context.metadata).toBeDefined();
    const headers = context.metadata?.headers as Record<string, string>;
    expect(headers["x-tenant-id"]).toBe("tenant-3");
    expect(headers["x-user-id"]).toBe("user-3");
  });
});
