import { lookup as dnsLookup } from "node:dns";
import { BlockList, isIP } from "node:net";
import { Agent, getGlobalDispatcher, fetch as undiciFetch } from "undici";

const SPECIAL_ADDRESSES = new BlockList();

for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  SPECIAL_ADDRESSES.addSubnet(network, prefix, "ipv4");
}

for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
  ["5f00::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
  ["ff00::", 8],
] as const) {
  SPECIAL_ADDRESSES.addSubnet(network, prefix, "ipv6");
}

export function isPrivateOrSpecialAddress(address: string): boolean {
  const normalized = address.toLowerCase().replace(/^\[|\]$/g, "");
  const family = isIP(normalized);
  if (family === 4) {
    return SPECIAL_ADDRESSES.check(normalized, "ipv4");
  }
  if (family === 6) {
    if (normalized.startsWith("::ffff:")) {
      return true;
    }
    return SPECIAL_ADDRESSES.check(normalized, "ipv6");
  }
  return false;
}

function blockedDnsError(hostname: string): NodeJS.ErrnoException {
  const error = new Error(
    `DNS resolution for ${hostname} returned a private or special-purpose address`,
  ) as NodeJS.ErrnoException;
  error.code = "EACCES";
  return error;
}

const publicOnlyAgent = new Agent({
  connect: {
    lookup(hostname, options, callback) {
      dnsLookup(hostname, { ...options, all: true }, (error, addresses) => {
        if (error) {
          callback(error, "", 4);
          return;
        }
        if (addresses.length === 0) {
          const noAddress = new Error(`DNS resolution for ${hostname} returned no addresses`);
          callback(noAddress, "", 4);
          return;
        }
        if (addresses.some(({ address }) => isPrivateOrSpecialAddress(address))) {
          callback(blockedDnsError(hostname), "", 4);
          return;
        }

        if (options.all) {
          callback(null, addresses);
          return;
        }
        const first = addresses[0];
        if (!first) {
          callback(new Error(`DNS resolution for ${hostname} returned no addresses`), "", 4);
          return;
        }
        callback(null, first.address, first.family);
      });
    },
  },
});

export async function networkPolicyFetch(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  allowPrivateNetwork: boolean,
): Promise<Response> {
  const dispatcher = allowPrivateNetwork ? getGlobalDispatcher() : publicOnlyAgent;
  return (await undiciFetch(input as Parameters<typeof undiciFetch>[0], {
    ...(init as Parameters<typeof undiciFetch>[1]),
    dispatcher,
  })) as unknown as Response;
}
