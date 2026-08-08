import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isPrivateOrSpecialAddress, networkPolicyFetch } from "../src/network";

describe("network policy", () => {
  const server = createServer((_request, response) => {
    response.setHeader("connection", "close");
    response.end("ok");
  });
  let url = "";

  beforeAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "localhost", () => resolve());
    });
    const address = server.address() as AddressInfo;
    url = `http://localhost:${address.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("classifies public, private, documentation, multicast, and mapped addresses", () => {
    expect(isPrivateOrSpecialAddress("8.8.8.8")).toBe(false);
    expect(isPrivateOrSpecialAddress("2606:4700:4700::1111")).toBe(false);
    for (const address of [
      "0.0.0.0",
      "10.0.0.1",
      "100.64.0.1",
      "192.0.2.1",
      "224.0.0.1",
      "240.0.0.1",
      "::1",
      "::ffff:8.8.8.8",
      "2001:db8::1",
      "fc00::1",
      "ff02::1",
    ]) {
      expect(isPrivateOrSpecialAddress(address), address).toBe(true);
    }
    expect(isPrivateOrSpecialAddress("not-an-ip")).toBe(false);
  });

  it("rejects a private DNS result unless the provider opted in", async () => {
    await expect(networkPolicyFetch(url, undefined, false)).rejects.toThrow();
    const response = await networkPolicyFetch(url, undefined, true);
    expect(await response.text()).toBe("ok");
  });
});
