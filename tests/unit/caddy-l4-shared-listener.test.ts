/**
 * L4 hosts on the HTTP server's port (SSH + MSSQL/TDS + LDAPS SNI on :443).
 *
 * TCP L4 hosts whose port the HTTP server (servers.cpm) already listens on must
 * become a `layer4` listener wrapper on that server, not a second listener on
 * the same port. Everything the L4 routes do not claim falls through to the
 * normal HTTPS handling.
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

import { createProxyHost } from '../../src/lib/models/proxy-hosts';
import { createL4ProxyHost, updateL4ProxyHost, type L4ProxyHostInput } from '../../src/lib/models/l4-proxy-hosts';
import { MSSQL_TDS_PRELOGIN_REGEXP } from '../../src/lib/l4-matchers';
import { buildCaddyDocument } from '../../src/lib/caddy';
import * as schema from '../../src/lib/db/schema';

type Doc = {
  apps: {
    http?: { servers?: { cpm?: { listen: string[]; listener_wrappers?: { wrapper: string; routes?: Record<string, unknown>[] }[] } } };
    layer4?: { servers: Record<string, { listen: string[]; routes: Record<string, unknown>[] }> };
  };
};

const ssh: L4ProxyHostInput = { name: 'ssh', protocol: 'tcp', listenAddress: ':443', upstreams: ['192.168.3.10:22'], matcherType: 'ssh' };
const mssql: L4ProxyHostInput = {
  name: 'mssql', protocol: 'tcp', listenAddress: ':443', upstreams: ['192.168.3.20:1433'],
  matcherType: 'regexp', matcherValue: [MSSQL_TDS_PRELOGIN_REGEXP.pattern],
  regexpMatcher: { hex: MSSQL_TDS_PRELOGIN_REGEXP.hex, count: MSSQL_TDS_PRELOGIN_REGEXP.count },
};
const ldaps: L4ProxyHostInput = {
  name: 'ldaps', protocol: 'tcp', listenAddress: ':443', upstreams: ['192.168.3.30:636'],
  matcherType: 'tls_sni', matcherValue: ['ldap.sweetie.bot'],
};

describe('L4 hosts sharing the HTTP port', () => {
  beforeEach(async () => {
    await ctx.db.delete(schema.l4ProxyHosts);
    await ctx.db.delete(schema.proxyHosts);
    await ctx.db.delete(schema.settings);
    await ctx.db.delete(schema.users).catch(() => {});
    await ctx.db.insert(schema.users).values({
      id: 1, email: 'admin@example.com', name: 'Admin', role: 'admin', provider: 'credentials',
      subject: 'admin', status: 'active', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    });
    await createProxyHost({ name: 'plain', domains: ['app.example.com'], upstreams: ['10.0.0.5:8080'] }, 1);
  });

  it('emits SSH, MSSQL and LDAPS SNI routes as a layer4 listener wrapper on servers.cpm', async () => {
    await createL4ProxyHost(ssh, 1);
    await createL4ProxyHost(mssql, 1);
    await createL4ProxyHost(ldaps, 1);

    const doc = (await buildCaddyDocument()) as unknown as Doc;
    const cpm = doc.apps.http!.servers!.cpm!;

    expect(cpm.listen).toContain(':443');
    // layer4 first, then tls: the order caddy-l4 requires (verified against a live Caddy).
    expect(cpm.listener_wrappers!.map((w) => w.wrapper)).toEqual(['layer4', 'tls']);
    expect(cpm.listener_wrappers![0].routes).toEqual([
      { match: [{ ssh: {} }], handle: [{ handler: 'proxy', upstreams: [{ dial: ['192.168.3.10:22'] }] }] },
      {
        match: [{ regexp: { pattern: '^12(00|01)0[0-9A-F]\\{3}0000[0-9A-F]\\{2}00$', count: 8, hex: true } }],
        handle: [{ handler: 'proxy', upstreams: [{ dial: ['192.168.3.20:1433'] }] }],
      },
      {
        match: [{ tls: { sni: ['ldap.sweetie.bot'] } }],
        handle: [{ handler: 'proxy', upstreams: [{ dial: ['192.168.3.30:636'] }] }],
      },
    ]);
    // No competing standalone layer4 server on :443.
    expect(doc.apps.layer4).toBeUndefined();
  });

  it('keeps ports the HTTP server does not own as standalone layer4 servers', async () => {
    await createL4ProxyHost({ ...ssh, listenAddress: ':2222' }, 1);
    const doc = (await buildCaddyDocument()) as unknown as Doc;
    expect(doc.apps.http!.servers!.cpm!.listener_wrappers).toBeUndefined();
    expect(Object.values(doc.apps.layer4!.servers).map((s) => s.listen)).toEqual([[':2222']]);
  });

  it('never wraps UDP hosts', async () => {
    await createL4ProxyHost({ name: 'dns', protocol: 'udp', listenAddress: ':443', upstreams: ['10.0.0.1:443'] }, 1);
    const doc = (await buildCaddyDocument()) as unknown as Doc;
    expect(doc.apps.http!.servers!.cpm!.listener_wrappers).toBeUndefined();
    expect(Object.values(doc.apps.layer4!.servers).map((s) => s.listen)).toEqual([['udp/:443']]);
  });

  it('puts catch-all hosts after specific matchers regardless of creation order', async () => {
    await createL4ProxyHost({ name: 'any', protocol: 'tcp', listenAddress: ':443', upstreams: ['10.9.9.9:1'] }, 1);
    await createL4ProxyHost(ssh, 1);
    const doc = (await buildCaddyDocument()) as unknown as Doc;
    const routes = doc.apps.http!.servers!.cpm!.listener_wrappers![0].routes!;
    expect(routes[0].match).toEqual([{ ssh: {} }]);
    expect(routes[1].match).toBeUndefined();
  });

  it('uses standalone layer4 servers when there is no HTTP server to share with', async () => {
    await ctx.db.delete(schema.proxyHosts);
    await createL4ProxyHost(ssh, 1);
    const doc = (await buildCaddyDocument()) as unknown as Doc;
    expect(doc.apps.http?.servers?.cpm).toBeUndefined();
    expect(Object.values(doc.apps.layer4!.servers).map((s) => s.listen)).toEqual([[':443']]);
  });

  it('persists regexp parameters across updates and drops them when the matcher type changes', async () => {
    const created = await createL4ProxyHost(mssql, 1);
    expect(created.regexpMatcher).toEqual({ hex: true, count: 8 });

    const renamed = await updateL4ProxyHost(created.id, { name: 'mssql2' }, 1);
    expect(renamed.regexpMatcher).toEqual({ hex: true, count: 8 });

    const asSsh = await updateL4ProxyHost(created.id, { matcherType: 'ssh', matcherValue: [] }, 1);
    expect(asSsh.regexpMatcher).toBeNull();
    expect(asSsh.meta?.regexp_matcher).toBeUndefined();
  });
});

describe('L4 matcher validation', () => {
  beforeEach(async () => {
    await ctx.db.delete(schema.users).catch(() => {});
    await ctx.db.insert(schema.users).values({
      id: 1, email: 'admin@example.com', name: 'Admin', role: 'admin', provider: 'credentials',
      subject: 'admin', status: 'active', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    });
  });

  const regexp = (pattern: string[], extra: Partial<L4ProxyHostInput> = {}): L4ProxyHostInput => ({
    ...mssql, matcherValue: pattern, ...extra,
  });

  it.each([
    [[], /exactly one pattern/],
    [[''], /exactly one pattern|requires a pattern/],
    [['a', 'b'], /exactly one pattern/],
    [['(?=x)'], /lookahead/],
    [['(a)\\1'], /backreferences/],
    [['('], /Invalid regexp/],
    [['a'.repeat(1025)], /at most 1024/],
  ])('rejects regexp pattern %j', async (pattern, message) => {
    await expect(createL4ProxyHost(regexp(pattern as string[]), 1)).rejects.toThrow(message);
  });

  it.each([0, -1, 1.5, 16385])('rejects bytes-to-inspect %s', async (count) => {
    await expect(createL4ProxyHost(regexp(['^a'], { regexpMatcher: { hex: false, count } }), 1)).rejects.toThrow(/between 1 and 16384/);
  });

  it('rejects SSH matcher on UDP', async () => {
    await expect(createL4ProxyHost({ ...ssh, protocol: 'udp' }, 1)).rejects.toThrow(/only supported with TCP/);
  });

  it('accepts a comma-bearing pattern as a single value', async () => {
    const host = await createL4ProxyHost(regexp(['^a{2,4}$'], { regexpMatcher: undefined }), 1);
    expect(host.matcherValue).toEqual(['^a{2,4}$']);
    expect(host.regexpMatcher).toEqual({ hex: false, count: 8 });
  });
});

describe('MSSQL TDS PRELOGIN signature', () => {
  // The pattern is matched by Go against the uppercase hex of the first 8 bytes;
  // it uses only syntax with identical JS/RE2 semantics.
  const re = new RegExp(MSSQL_TDS_PRELOGIN_REGEXP.pattern);
  const hex = (bytes: number[]) => Buffer.from(bytes).toString('hex').toUpperCase();

  it.each([
    ['Microsoft client PRELOGIN (len 0x2F, packet id 0)', [0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00]],
    ['packet id 1', [0x12, 0x01, 0x00, 0x58, 0x00, 0x00, 0x01, 0x00]],
    ['status 0 (non-EOM)', [0x12, 0x00, 0x0f, 0xff, 0x00, 0x00, 0x00, 0x00]],
  ])('matches %s', (_n, bytes) => {
    expect(re.test(hex(bytes))).toBe(true);
  });

  it.each([
    ['TLS 1.2/1.3 ClientHello record', [0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01]],
    ['SSH banner', [...Buffer.from('SSH-2.0-')]],
    ['HTTP request', [...Buffer.from('GET / HT')]],
    ['HTTP/2 preface', [...Buffer.from('PRI * HT')]],
    ['TDS SQL batch (0x01), not PRELOGIN', [0x01, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00]],
    ['0x12 but non-zero SPID', [0x12, 0x01, 0x00, 0x2f, 0x00, 0x01, 0x00, 0x00]],
    ['0x12 but non-zero window', [0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x01]],
    ['0x12 with reserved status bits', [0x12, 0x09, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00]],
    ['0x12 with length >= 4096', [0x12, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00]],
  ])('does not match %s', (_n, bytes) => {
    expect(re.test(hex(bytes))).toBe(false);
  });
});

describe('protocol-signature L4 matchers (RDP, SOCKS4/5, WireGuard, XMPP, Postgres, Winbox, OpenVPN)', () => {
  beforeEach(async () => {
    await ctx.db.delete(schema.l4ProxyHosts);
    await ctx.db.delete(schema.users).catch(() => {});
    await ctx.db.insert(schema.users).values({
      id: 1, email: 'admin@example.com', name: 'Admin', role: 'admin', provider: 'credentials',
      subject: 'admin', status: 'active', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    });
  });

  const TCP_ONLY = ['rdp', 'socks4', 'socks5', 'postgres', 'winbox'] as const;
  const NOT_TCP_ONLY = ['wireguard', 'xmpp', 'openvpn'] as const;

  it.each([...TCP_ONLY, ...NOT_TCP_ONLY])('emits an empty %s matcher object with no matcherValue', async (matcherType) => {
    const host = await createL4ProxyHost(
      { name: matcherType, protocol: 'tcp', listenAddress: ':1234', upstreams: ['10.0.0.1:1'], matcherType },
      1
    );
    expect(host.matcherValue).toEqual([]);

    const doc = (await buildCaddyDocument()) as unknown as Doc;
    const route = doc.apps.layer4!.servers['l4_server_0'].routes[0];
    expect(route.match).toEqual([{ [matcherType]: {} }]);
  });

  it.each(TCP_ONLY)('rejects %s matcher on UDP', async (matcherType) => {
    await expect(
      createL4ProxyHost({ name: 'x', protocol: 'udp', listenAddress: ':1234', upstreams: ['10.0.0.1:1'], matcherType }, 1)
    ).rejects.toThrow(/only supported with TCP/);
  });

  it.each(NOT_TCP_ONLY)('allows %s matcher on UDP', async (matcherType) => {
    const host = await createL4ProxyHost(
      { name: 'x', protocol: 'udp', listenAddress: ':1234', upstreams: ['10.0.0.1:1'], matcherType },
      1
    );
    expect(host.matcherType).toBe(matcherType);
  });
});
