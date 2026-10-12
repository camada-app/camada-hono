// Off Workers there is no `request.cf` and no `cf-connecting-ip` to trust, so the socket peer has to
// come from the runtime object Hono hands the app as `c.env` (camada-all-kri7):
//   @hono/node-server  app.fetch(req, { incoming, outgoing })  → incoming.socket.remoteAddress
//   Bun.serve({ fetch: app.fetch })  app.fetch(req, server)     → server.requestIP(req).address
//   Deno.serve(app.fetch)  app.fetch(req, info)                 → info.remoteAddr.hostname
// or from the app's own `peer(c)`. Each runtime is driven here with the exact env shape it passes.
// Also: off Workers there is no waitUntil, so rows must not each POST /e on their own (the queue's
// timer batches them); on Workers every row still flushes through waitUntil.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Hono } from 'hono';
import { camada, resetCamada, type CamadaHonoOptions } from '../src/index.js';

const FIX = fileURLToPath(new URL('../node_modules/@camada/core/test/fixtures/blk3/', import.meta.url));
const bin = readFileSync(FIX + 'v4-basic.bin');
const meta = JSON.stringify(JSON.parse(readFileSync(FIX + 'v4-basic.meta.json', 'utf8')));
const BLOCKED_IP = '203.0.113.66';   // block side of the golden v4 container
const CONFIG = { tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 };
const ENV = { CAMADA_KEY: 'tok-acme.snap-acme', CAMADA_INGEST_URL: 'http://analyst.test', CAMADA_SNAPSHOT_URL: 'http://analyst.test/snapshot' };

let posts: number;
let events: Array<Record<string, unknown>>;
const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
  if (String(url).endsWith('/snapshot')) {
    const m = new TextEncoder().encode(meta);
    const f = new Uint8Array(4 + m.length + bin.length);
    new DataView(f.buffer).setUint32(0, m.length, true);
    f.set(m, 4); f.set(new Uint8Array(bin), 4 + m.length);
    return new Response(f, { status: 200, headers: { etag: '"v4"', 'x-camada-config': JSON.stringify(CONFIG) } });
  }
  posts++;
  events.push(...(JSON.parse(String(init?.body)) as Array<Record<string, unknown>>));
  return new Response(null, { status: 202 });
}) as typeof fetch;

beforeEach(() => { posts = 0; events = []; resetCamada(); });
afterEach(() => resetCamada());

function app(opts: CamadaHonoOptions = {}): Hono {
  const a = new Hono();
  a.use('*', camada({ env: ENV, fetchImpl, ...opts }));
  a.get('/', (c) => c.text('home'));
  return a;
}

type Env = (req: Request) => unknown;
const runtimes: Record<string, Env> = {
  'node-server': () => ({ incoming: { socket: { remoteAddress: '::ffff:' + BLOCKED_IP } }, outgoing: {} }),
  'Bun (server as env)': () => ({ requestIP: () => ({ address: BLOCKED_IP, family: 'IPv4', port: 5555 }), upgrade: () => false }),
  'Bun (hono/bun { server })': () => ({ server: { requestIP: () => ({ address: BLOCKED_IP, family: 'IPv4', port: 5555 }) } }),
  'Deno': () => ({ remoteAddr: { transport: 'tcp', hostname: BLOCKED_IP, port: 5555 }, completed: Promise.resolve() }),
};

/** One request as the runtime delivers it: no `request.cf`, no execution context. */
async function offWorkers(a: Hono, env: Env | null, path = '/', headers: Record<string, string> = {}): Promise<Response> {
  const req = new Request(`http://app.test${path}`, { headers });
  const res = await a.fetch(req, env ? env(req) : undefined);
  await res.arrayBuffer();
  return res;
}

/** Cold request loads the snapshot (fail open); later ones enforce. */
async function primed(a: Hono, env: Env | null): Promise<void> {
  await offWorkers(a, env);
  await new Promise((r) => setTimeout(r, 0));
}

describe('socket peer off Workers (camada-all-kri7)', () => {
  for (const [name, env] of Object.entries(runtimes)) {
    it(`${name}: takes the peer from the runtime and enforces an ip block on it`, async () => {
      const a = app();
      await primed(a, null);
      const res = await offWorkers(a, env);
      expect(res.status).toBe(403);
      expect(res.headers.get('x-block-reason')).toBe('ip4');
    });
  }

  it('without a runtime peer the address stays unknown (no block)', async () => {
    const a = app();
    await primed(a, null);
    expect((await offWorkers(a, null)).status).toBe(200);
    expect((await offWorkers(a, () => ({ requestIP: () => null }))).status).toBe(200);   // a Bun request detached by upgrade
  });

  it('a peer(c) option wins over the runtime object', async () => {
    const a = app({ peer: () => BLOCKED_IP });
    await primed(a, null);
    expect((await offWorkers(a, null)).status).toBe(403);
    const b = app({ peer: () => '8.8.8.8' });
    expect((await offWorkers(b, runtimes['node-server']!)).status).toBe(200);
  });

  it('a throwing peer(c) or runtime getter fails open', async () => {
    const a = app({ peer: () => { throw new Error('boom'); } });
    await primed(a, null);
    expect((await offWorkers(a, () => ({ get incoming() { throw new Error('boom'); } }))).status).toBe(200);
  });

  it('a trusted proxy still walks X-Forwarded-For from the runtime peer', async () => {
    const a = app({ trustedProxy: 'hops:1' });
    await primed(a, null);
    const peer = () => ({ incoming: { socket: { remoteAddress: '10.1.2.3' } } });
    expect((await offWorkers(a, peer, '/', { 'x-forwarded-for': BLOCKED_IP })).status).toBe(403);
  });

  it('on Workers keeps cf-connecting-ip and never reads the env as a runtime object', async () => {
    const a = app();
    const call = async (headers: Record<string, string>, env: unknown) => {
      const req = new Request('http://app.test/', { headers });
      Object.defineProperty(req, 'cf', { value: {} });
      const waits: Promise<unknown>[] = [];
      const res = await a.fetch(req, env, { waitUntil: (p: Promise<unknown>) => waits.push(p), passThroughOnException: () => {} } as never);
      await res.arrayBuffer(); await Promise.all(waits);
      return res;
    };
    await call({}, {}); await call({}, {});
    expect((await call({ 'cf-connecting-ip': BLOCKED_IP }, {})).status).toBe(403);
    // A binding that happens to look like node-server's incoming is ignored where request.cf exists.
    expect((await call({ 'cf-connecting-ip': '8.8.8.8' }, { incoming: { socket: { remoteAddress: BLOCKED_IP } } })).status).toBe(200);
  });
});

describe('flushing off Workers (hono ship(), the 7u3r rule)', () => {
  it('does not POST /e per request without a waitUntil: the queue timer batches the rows', async () => {
    const a = app();
    for (let i = 0; i < 5; i++) await offWorkers(a, runtimes['node-server']!);
    await new Promise((r) => setTimeout(r, 20));
    expect(posts).toBe(0);
  });

  it('still flushes every row through waitUntil on Workers', async () => {
    const a = app();
    for (let i = 0; i < 3; i++) {
      const req = new Request('http://app.test/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
      Object.defineProperty(req, 'cf', { value: {} });
      const waits: Promise<unknown>[] = [];
      const res = await a.fetch(req, {}, { waitUntil: (p: Promise<unknown>) => waits.push(p), passThroughOnException: () => {} } as never);
      await res.arrayBuffer(); await Promise.all(waits);
    }
    expect(posts).toBeGreaterThanOrEqual(1);
    expect(events.filter((e) => e.p === '/')).toHaveLength(3);
  });
});
