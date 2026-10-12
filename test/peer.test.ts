// Off Workers there is no `request.cf` and no `cf-connecting-ip` to trust, so the socket peer has to
// come from the runtime object Hono hands the app as `c.env` (camada-all-kri7):
//   @hono/node-server  app.fetch(req, { incoming, outgoing })  → incoming.socket.remoteAddress
//   Bun.serve({ fetch: app.fetch })  app.fetch(req, server)     → server.requestIP(req).address
//   Deno.serve(app.fetch)  app.fetch(req, info)                 → info.remoteAddr.hostname
// or from the app's own `peer(c)`. Each runtime is driven here with the exact env shape it passes.
// Also: off Workers there is no waitUntil, so rows must not each POST /e on their own (the queue's
// timer batches them); on Workers every row still flushes through waitUntil.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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

const HOST_VARS = ['VERCEL', 'AWS_LAMBDA_FUNCTION_NAME', 'NETLIFY', 'DENO_DEPLOYMENT_ID', 'CAMADA_SERVERLESS'];
beforeEach(() => {
  posts = 0; events = []; resetCamada();
  for (const k of HOST_VARS) vi.stubEnv(k, undefined as unknown as string);   // the runner's own host must not decide these cases
});
afterEach(() => { resetCamada(); vi.unstubAllEnvs(); vi.unstubAllGlobals(); vi.useRealTimers(); });

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
/** Each runtime shape is read only where that runtime is the one running (camada-all R4-6). */
function asRuntime(name: string): void {
  if (name.startsWith('Bun')) vi.stubGlobal('Bun', { version: '1.2.0' });
  if (name === 'Deno') vi.stubGlobal('Deno', { version: { deno: '2.1.0' } });
}

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
      asRuntime(name);
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
  /** N requests through `app.fetch(req, env)`, one tick apart, so a per-row flush has settled before the next. */
  async function requests(a: Hono, n: number, env: Env | null, path = '/'): Promise<void> {
    for (let i = 0; i < n; i++) { await offWorkers(a, env, path); await new Promise((r) => setTimeout(r, 0)); }
  }
  const pageRows = () => events.filter((e) => e.p === '/');

  it('a long-lived node server batches on the queue timer: 5 requests, 15 s → exactly 1 POST of 5 rows', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    const a = app();
    await requests(a, 5, runtimes['node-server']!);
    expect(posts).toBe(0);
    await vi.advanceTimersByTimeAsync(15_000);
    expect(posts).toBe(1);
    expect(pageRows()).toHaveLength(5);
  });

  it('a long-lived node server drains what is queued on beforeExit', async () => {
    const a = app();
    await requests(a, 3, runtimes['node-server']!);
    expect(posts).toBe(0);
    process.emit('beforeExit', 0);
    await new Promise((r) => setTimeout(r, 0));
    expect(posts).toBe(1);
    expect(pageRows()).toHaveLength(3);
  });

  for (const name of ['Bun (server as env)', 'Deno']) {
    it(`${name}: batches too`, async () => {
      asRuntime(name);
      const a = app();
      await requests(a, 3, () => runtimes[name]!(new Request('http://x/')));
      expect(posts).toBe(0);
    });
  }

  // hono/vercel, hono/netlify, hono/aws-lambda and hono/lambda-edge pass no execution context
  // either, but the function freezes after the response: a row left for the 15 s timer is lost.
  const serverless: Record<string, Env | null> = {
    'hono/vercel handle(app)': null,
    'hono/netlify handle(app)': () => ({ context: { requestId: 'r1' } }),
    'hono/aws-lambda handle(app)': () => ({ event: {}, requestContext: {}, lambdaContext: {} }),
    'hono/lambda-edge handle(app)': () => ({ event: {}, context: {}, callback: () => {}, config: {} }),
  };
  for (const [name, env] of Object.entries(serverless)) {
    it(`${name}: flushes every row (N POSTs for N requests) and installs no exit handler`, async () => {
      const before = process.listenerCount('beforeExit');
      const a = app();
      await requests(a, 3, env);
      expect(posts).toBe(3);
      expect(pageRows()).toHaveLength(3);
      expect(process.listenerCount('beforeExit')).toBe(before);
    });
  }

  for (const k of ['VERCEL', 'AWS_LAMBDA_FUNCTION_NAME', 'NETLIFY', 'DENO_DEPLOYMENT_ID', 'CAMADA_SERVERLESS']) {
    it(`a node-server shape with ${k} set flushes per row (@hono/node-server/vercel and the like)`, async () => {
      vi.stubEnv(k, '1');
      const a = app();
      await requests(a, 3, runtimes['node-server']!);
      expect(posts).toBe(3);
    });
  }

  it("mode: 'timer' batches even where no server shape is recognised", async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    const a = app({ mode: 'timer' });
    await requests(a, 3, null);
    expect(posts).toBe(0);
    await vi.advanceTimersByTimeAsync(15_000);
    expect(posts).toBe(1);
    expect(pageRows()).toHaveLength(3);
  });

  it("mode: 'lazy' flushes per row on a node server; CAMADA_SERVERLESS=1 beats mode: 'timer'", async () => {
    await requests(app({ mode: 'lazy' }), 2, runtimes['node-server']!);
    expect(posts).toBe(2);
    resetCamada(); posts = 0;
    await requests(app({ mode: 'timer', env: { ...ENV, CAMADA_SERVERLESS: '1' } }), 2, null);
    expect(posts).toBe(2);
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

describe('Workers bindings are never read as a runtime object (R4-6)', () => {
  it('with an execution context and no request.cf, a JS-RPC binding named `server` is never called', async () => {
    vi.stubGlobal('Bun', { version: '1.2.0' });   // even where the Bun global exists
    const calls: string[] = [];
    // A service-binding stub answers every property with a callable RPC method.
    const rpc = new Proxy({}, { get: (_t, k) => (typeof k === 'string' ? (...a: unknown[]) => { calls.push(k); void a; return Promise.reject(new Error('rpc')); } : undefined) });
    const a = app();
    for (let i = 0; i < 2; i++) {
      const waits: Promise<unknown>[] = [];
      const res = await a.fetch(new Request('http://app.test/'), { server: rpc, incoming: rpc }, { waitUntil: (p: Promise<unknown>) => waits.push(p), passThroughOnException: () => {} } as never);
      await res.arrayBuffer(); await Promise.all(waits);
    }
    expect(calls).not.toContain('requestIP');
    expect(calls).toEqual([]);
  });

  it('a Bun-shaped env is not read on Node, a Deno-shaped env not off Deno', async () => {
    const a = app();
    await primed(a, null);
    expect((await offWorkers(a, runtimes['Bun (server as env)']!)).status).toBe(200);
    expect((await offWorkers(a, runtimes['Deno']!)).status).toBe(200);
  });
});

describe('trusted proxy default on Vercel (R4-7)', () => {
  it('VERCEL=1 with a node-server shape takes the rightmost X-Forwarded-For entry', async () => {
    vi.stubEnv('VERCEL', '1');
    const a = app();
    await primed(a, null);
    const peer = () => ({ incoming: { socket: { remoteAddress: '8.8.4.4' } } });
    expect((await offWorkers(a, peer, '/', { 'x-forwarded-for': `8.8.8.8, ${BLOCKED_IP}` })).status).toBe(403);
    expect((await offWorkers(a, peer, '/', { 'x-forwarded-for': `${BLOCKED_IP}, 8.8.8.8` })).status).toBe(200);
  });

  it('CAMADA_TRUSTED_PROXY still wins over the Vercel default', async () => {
    vi.stubEnv('VERCEL', '1');
    const a = app({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'none' } });
    await primed(a, null);
    const peer = () => ({ incoming: { socket: { remoteAddress: '8.8.4.4' } } });
    expect((await offWorkers(a, peer, '/', { 'x-forwarded-for': `8.8.8.8, ${BLOCKED_IP}` })).status).toBe(200);
  });
});
