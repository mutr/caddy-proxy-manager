/**
 * Per-location-rule path-prefix rewrite.
 *
 * Verifies the model layer hydrates/dehydrates a location rule's rewriteTo
 * field, that it survives an unrelated update, and that buildCaddyDocument
 * emits a `rewrite` handler (uri_substring) immediately before the location's
 * reverse_proxy when set — and emits nothing extra when it is not set.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  const schemaModule = await import('../../src/lib/db/schema');
  ctx.db = createTestDb();
  return {
    default: ctx.db,
    sqlite: undefined,
    schema: schemaModule,
    nowIso: () => new Date().toISOString(),
    toIso: (value: string | Date | null | undefined): string | null => {
      if (!value) return null;
      return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
    },
  };
});

vi.mock('../../src/lib/caddy', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/caddy')>();
  return { ...actual, applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }) };
});

vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

import { createProxyHost, updateProxyHost, getProxyHost } from '../../src/lib/models/proxy-hosts';
import { buildCaddyDocument } from '../../src/lib/caddy';
import * as schema from '../../src/lib/db/schema';

beforeEach(async () => {
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.users).catch(() => {});
  await ctx.db.insert(schema.users).values({
    id: 1,
    email: 'admin@example.com',
    name: 'Admin',
    role: 'admin',
    provider: 'credentials',
    subject: 'admin',
    status: 'active',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
});

describe('location rule rewriteTo — model round-trip', () => {
  it('hydrates an empty-string rewriteTo (strip prefix) on read', async () => {
    const host = await createProxyHost(
      {
        name: 'Strip Rule Host',
        domains: ['strip.example.com'],
        upstreams: ['origin:80'],
        locationRules: [{ path: '/trans/*', upstreams: ['backend:5002'], rewriteTo: '' }],
      },
      1
    );
    const fetched = (await getProxyHost(host.id))!;
    expect(fetched.locationRules[0].rewriteTo).toBe('');
  });

  it('hydrates a non-empty rewriteTo (prefix remap) on read', async () => {
    const host = await createProxyHost(
      {
        name: 'Remap Rule Host',
        domains: ['remap.example.com'],
        upstreams: ['origin:80'],
        locationRules: [{ path: '/v2/*', upstreams: ['nexus:8081'], rewriteTo: '/repository/docker_io/v2' }],
      },
      1
    );
    const fetched = (await getProxyHost(host.id))!;
    expect(fetched.locationRules[0].rewriteTo).toBe('/repository/docker_io/v2');
  });

  it('leaves rewriteTo null when not supplied (default, unchanged behavior)', async () => {
    const host = await createProxyHost(
      {
        name: 'Plain Rule Host',
        domains: ['plain.example.com'],
        upstreams: ['origin:80'],
        locationRules: [{ path: '/api/*', upstreams: ['api:3000'] }],
      },
      1
    );
    const fetched = (await getProxyHost(host.id))!;
    expect(fetched.locationRules[0].rewriteTo).toBeNull();
  });

  it('preserves rewriteTo across an unrelated update', async () => {
    const host = await createProxyHost(
      {
        name: 'Persist Rule Host',
        domains: ['persist.example.com'],
        upstreams: ['origin:80'],
        locationRules: [{ path: '/trans/*', upstreams: ['backend:5002'], rewriteTo: '' }],
      },
      1
    );
    await updateProxyHost(host.id, { name: 'Renamed' }, 1);
    const fetched = (await getProxyHost(host.id))!;

    expect(fetched.name).toBe('Renamed');
    expect(fetched.locationRules[0].rewriteTo).toBe('');
  });
});

describe('location rule rewriteTo — generated Caddy config', () => {
  it('emits a rewrite handler with uri_substring before the reverse_proxy for a strip rule', async () => {
    await createProxyHost(
      {
        name: 'Strip Doc Host',
        domains: ['stripdoc.example.com'],
        upstreams: ['origin:80'],
        locationRules: [{ path: '/trans/*', upstreams: ['backend:5002'], rewriteTo: '' }],
      },
      1
    );
    const doc = await buildCaddyDocument();
    const docStr = JSON.stringify(doc);
    expect(docStr).toContain('"uri_substring"');
    expect(docStr).toContain('"find":"/trans"');

    const routes = findRoutesForHost(doc, 'stripdoc.example.com');
    const rule = routes.find((r) => JSON.stringify(r.match).includes('/trans/*'));
    expect(rule).toBeTruthy();
    const handlerNames = rule!.handle.map((h: Record<string, unknown>) => h.handler);
    const rewriteIdx = handlerNames.indexOf('rewrite');
    const proxyIdx = handlerNames.indexOf('reverse_proxy');
    expect(rewriteIdx).toBeGreaterThanOrEqual(0);
    expect(proxyIdx).toBeGreaterThan(rewriteIdx);
  });

  it('emits a rewrite handler that replaces the prefix for a remap rule', async () => {
    await createProxyHost(
      {
        name: 'Remap Doc Host',
        domains: ['remapdoc.example.com'],
        upstreams: ['origin:80'],
        locationRules: [{ path: '/v2/*', upstreams: ['nexus:8081'], rewriteTo: '/repository/docker_io/v2' }],
      },
      1
    );
    const doc = await buildCaddyDocument();
    const docStr = JSON.stringify(doc);
    expect(docStr).toContain('"find":"/v2"');
    expect(docStr).toContain('"replace":"/repository/docker_io/v2"');
  });

  it('does not emit a rewrite handler when rewriteTo is not set', async () => {
    await createProxyHost(
      {
        name: 'NoRewrite Doc Host',
        domains: ['norewrite.example.com'],
        upstreams: ['origin:80'],
        locationRules: [{ path: '/api/*', upstreams: ['api:3000'] }],
      },
      1
    );
    const doc = await buildCaddyDocument();
    const routes = findRoutesForHost(doc, 'norewrite.example.com');
    const rule = routes.find((r) => JSON.stringify(r.match).includes('/api/*'));
    expect(rule).toBeTruthy();
    const handlerNames = rule!.handle.map((h: Record<string, unknown>) => h.handler);
    expect(handlerNames).not.toContain('rewrite');
  });
});

type CaddyRoute = { match: unknown[]; handle: Record<string, unknown>[] };

function findRoutesForHost(doc: unknown, domain: string): CaddyRoute[] {
  const servers = (doc as { apps: { http: { servers: Record<string, { routes: CaddyRoute[] }> } } }).apps.http
    .servers;
  const allRoutes: CaddyRoute[] = [];
  for (const server of Object.values(servers)) {
    for (const route of server.routes) {
      if (JSON.stringify(route.match).includes(domain)) {
        allRoutes.push(route);
      }
    }
  }
  return allRoutes;
}
