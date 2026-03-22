import { describe, expect, it, vi } from 'vitest';
import { createBearerAuthAdapter, createStaticProviderResolver } from '../src';

describe('adapter helpers', () => {
  it('createStaticProviderResolver resolves configured provider', async () => {
    const resolver = createStaticProviderResolver({
      billing: {
        id: 'billing',
        baseUrl: 'https://billing.example.com'
      }
    });

    const provider = await resolver('billing');
    expect(provider?.id).toBe('billing');
  });

  it('createStaticProviderResolver calls onNotFound hook', async () => {
    const onNotFound = vi.fn();
    const resolver = createStaticProviderResolver({}, { onNotFound });

    const provider = await resolver('missing', { tenantId: 't1' });
    expect(provider).toBeNull();
    expect(onNotFound).toHaveBeenCalledWith('missing', { tenantId: 't1' });
  });

  it('createBearerAuthAdapter returns authorization header', async () => {
    const adapter = createBearerAuthAdapter(({ context }) => {
      return context?.metadata?.token as string | undefined;
    });

    const header = await adapter.resolveAuthHeader({
      provider: { id: 'p1', baseUrl: 'https://example.com' },
      context: { metadata: { token: 'abc123' } }
    });

    expect(header).toEqual({
      headerName: 'authorization',
      headerValue: 'Bearer abc123'
    });
  });

  it('createBearerAuthAdapter supports custom header and scheme', async () => {
    const adapter = createBearerAuthAdapter(() => 'k1', {
      headerName: 'x-api-key',
      scheme: 'Token'
    });

    const header = await adapter.resolveAuthHeader({
      provider: { id: 'p1', baseUrl: 'https://example.com' }
    });

    expect(header).toEqual({
      headerName: 'x-api-key',
      headerValue: 'Token k1'
    });
  });

  it('createBearerAuthAdapter returns null when no token', async () => {
    const adapter = createBearerAuthAdapter(() => null);
    const header = await adapter.resolveAuthHeader({
      provider: { id: 'p1', baseUrl: 'https://example.com' }
    });

    expect(header).toBeNull();
  });
});
