import type {
  AuthAdapter,
  ProviderConfig,
  ProviderResolver,
  RequestContext,
  ResolvedAuthHeader,
} from "./types";

export interface StaticProviderResolverOptions {
  onNotFound?: (providerId: string, context?: RequestContext) => void | Promise<void>;
}

export function createStaticProviderResolver(
  providers: Record<string, ProviderConfig>,
  options: StaticProviderResolverOptions = {},
): ProviderResolver {
  return async (providerId, context) => {
    const provider = providers[providerId];
    if (!provider) {
      if (options.onNotFound) {
        await options.onNotFound(providerId, context);
      }
      return null;
    }
    return provider;
  };
}

export interface BearerAuthAdapterOptions {
  headerName?: string;
  scheme?: string;
}

export type AccessTokenResolver = (input: {
  provider: ProviderConfig;
  context?: RequestContext;
}) => Promise<string | null | undefined> | string | null | undefined;

export function createBearerAuthAdapter(
  resolveAccessToken: AccessTokenResolver,
  options: BearerAuthAdapterOptions = {},
): AuthAdapter {
  const headerName = options.headerName ?? "authorization";
  const scheme = options.scheme ?? "Bearer";

  return {
    async resolveAuthHeader(input): Promise<ResolvedAuthHeader | null> {
      const token = await resolveAccessToken(input);
      if (!token) {
        return null;
      }
      return {
        headerName,
        headerValue: `${scheme} ${token}`,
      };
    },
  };
}
