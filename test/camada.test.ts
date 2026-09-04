// @camada/hono against the golden v4 snapshot, driven through a real Hono app with
// app.request(). The fixtures are read through the file: symlink to @camada/core, so this
// package is pinned to the same bytes edge-analyst generates.
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Hono } from 'hono';
import { CHALLENGE_COOKIE } from '@camada/core';
import { camada, resetCamada, type CamadaHonoOptions } from '../src/index.js';

const FIX = fileURLToPath(new URL('../node_modules/@camada/core/test/fixtures/blk3/', import.meta.url));
const BIN = readFileSync(FIX + 'v4-basic.bin');
const META = JSON.stringify(JSON.parse(readFileSync(FIX + 'v4-basic.meta.json', 'utf8')));

const BLOCKED_IP = '203.0.113.66';     // block side
const CHALLENGED_IP = '192.0.2.20';    // challenge side only
const ALLOWED_IP = '10.0.0.7';         // allow-listed inside the blocked 10.0.0.0/8
const HTML = { accept: 'text/html', 'sec-fetch-dest': 'document' };

const CONFIG = { tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 };
const ENV = { CAMADA_KEY: 'tok-acme.snap-acme', CAMADA_INGEST_URL: 'http://analyst.test', CAMADA_SNAPSHOT_URL: 'http://analyst.test/snapshot' };

// 200 body frame: [u32 LE meta-length][meta JSON][BLK3 bin]
function frame(): ArrayBuffer {
  const m = new TextEncoder().encode(META);
  const f = new Uint8Array(4 + m.length + BIN.length);
  new DataView(f.buffer).setUint32(0, m.length, true);
  f.set(m, 4); f.set(new Uint8Array(BIN), 4 + m.length);
  return f.buffer;
}

let events: Array<Record<string, unknown>>;
let sdkHeaders: string[];
let snapshotVersions: string[];
let tenantTokens: string[];   // the x-tenant each batch shipped under

const fetchImpl: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
  const u = String(url);
  if (u.endsWith('/snapshot')) {
    snapshotVersions.push(new Headers(init?.headers).get('x-camada-snapshot') ?? '');
    return new Response(frame(), { status: 200, headers: { etag: '"fixture-v4-basic"', 'x-camada-config': JSON.stringify(CONFIG) } });
  }
  sdkHeaders.push(new Headers(init?.headers).get('x-camada-sdk') ?? '');
  tenantTokens.push(new Headers(init?.headers).get('x-tenant') ?? '');
  events.push(...(JSON.parse(String(init?.body)) as Array<Record<string, unknown>>));
  return new Response(null, { status: 202 });
}) as typeof fetch;

function app(opts: CamadaHonoOptions = {}): Hono {
  const a = new Hono();
  a.use('*', camada({ env: ENV, fetchImpl, ...opts }));
  a.get('/', (c) => c.text('home'));
  a.get('/cart', (c) => c.html('<p>cart</p>'));
  a.get('/checkout', (c) => c.html('<p>checkout</p>'));
  a.get('/admin/users', (c) => c.html('<p>admin</p>'));
  a.get('/missing-route-is-404', (c) => c.notFound());
  return a;
}

/** A stand-in Workers execution context that records what the middleware hands to waitUntil. */
function executionCtx(): { ctx: never; settle: () => Promise<unknown> } {
  const waits: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => waits.push(p), passThroughOnException: () => {} };
  return { ctx: ctx as never, settle: () => Promise.all(waits) };
}

/** Drives one request as Workers would deliver it — `request.cf` present, which is what makes
 *  `cf-connecting-ip` trustworthy. `cf: null` drives the same request on a non-Workers runtime. */
async function call(a: Hono, path: string, init: RequestInit = {}, cf: Record<string, unknown> | null = {}): Promise<Response> {
  const req = new Request(`http://app.test${path}`, init);
  if (cf) Object.defineProperty(req, 'cf', { value: cf });
  const { ctx, settle } = executionCtx();
  const res = await a.fetch(req, {}, ctx);
  await settle();
  return res;
}

/** Drives a raw Request with the `cf` properties Workers would attach. */
const callWithCf = (a: Hono, cf: Record<string, unknown>, headers: Record<string, string>): Promise<Response> =>
  call(a, '/', { headers }, cf);

/** Posts a challenge solution the way the proof-of-work page does. */
function postSolution(a: Hono, ip: string, body: string): Promise<Response> {
  return call(a, '/__camada/challenge', {
    method: 'POST',
    headers: { 'cf-connecting-ip': ip, 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
}

/** The first request is cold (fail open) and loads the snapshot. */
async function primed(opts: CamadaHonoOptions = {}): Promise<Hono> {
  const a = app(opts);
  await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
  await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });   // second request sees the loaded snapshot
  events.length = 0;
  return a;
}

const nonceOf = (page: string) => /name="nonce" value="([0-9a-f]{32})"/.exec(page)![1];
const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};

beforeEach(() => { events = []; sdkHeaders = []; snapshotVersions = []; tenantTokens = []; resetCamada(); });

describe('capture', () => {
  it('lets an unlisted request through and ships the event with the real status', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(res.status).toBe(200);
    expect(events.some((e) => e.tap === 'sdk-hono' && e.p === '/' && e.st === 200)).toBe(true);
  });

  it('reports its identity on every batch and asks for the v4 snapshot', async () => {
    const a = await primed();
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(snapshotVersions[0]).toBe('4');
    expect(sdkHeaders.length).toBeGreaterThan(0);
    expect(sdkHeaders.every((h) => /^@camada\/hono\/\d+\.\d+\.\d+$/.test(h))).toBe(true);
  });

  it('reports the client protocol from request.cf, never a forwarded header', async () => {
    const a = await primed();
    await callWithCf(a, { httpProtocol: 'HTTP/2' }, { 'cf-connecting-ip': '8.8.8.8', 'x-forwarded-proto': 'http' });
    expect(events.at(-1)).toMatchObject({ proto: 'HTTP/2' });
  });

  it('leaves the protocol null when Workers does not supply one', async () => {
    const a = await primed();
    await callWithCf(a, {}, { 'cf-connecting-ip': '8.8.8.8' });
    expect(events.at(-1)!.proto).toBeNull();
  });

  it('carries the asn, country and tls fingerprint Workers hands it', async () => {
    const a = await primed();
    await callWithCf(a, { asn: 13335, country: 'US', tlsClientExtensionsSha1: 'abc123', httpProtocol: 'HTTP/3' }, { 'cf-connecting-ip': '8.8.8.8' });
    expect(events.at(-1)).toMatchObject({ asn: 13335, cc: 'US', tlsx: 'abc123', proto: 'HTTP/3' });
  });
});

describe('enforcement', () => {
  it('blocks a listed ip with 403 and blk', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': BLOCKED_IP } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('ip4');
    expect(res.headers.get('x-block-version')).toBeTruthy();
    expect(events.some((e) => e.st === 403 && e.blk === 'ip4')).toBe(true);
  });

  it('honours the v4 allow side over a wider block', async () => {
    const a = await primed();
    expect((await call(a, '/', { headers: { 'cf-connecting-ip': ALLOWED_IP } })).status).toBe(200);
  });

  it('enforces an asn rule, which a bare Node tap cannot see', async () => {
    const a = await primed();
    const res = await callWithCf(a, { asn: 64512 }, { 'cf-connecting-ip': '8.8.8.8', ...HTML });   // the challenge side's asn
    expect(res.status).toBe(403);
    expect(res.headers.get('x-camada-challenge')).toBe('1');
  });
});

describe('challenge', () => {
  it('serves the page, verifies the solution, and lets the cookie holder through', async () => {
    const a = await primed();
    const page = await call(a, '/cart', { headers: { 'cf-connecting-ip': CHALLENGED_IP, ...HTML } });
    expect(page.status).toBe(403);
    expect(page.headers.get('cache-control')).toBe('no-store');
    const nonce = nonceOf(await page.text());
    expect(events.some((e) => e.st === 403 && e.blk === 'challenge')).toBe(true);

    const ok = await postSolution(a, CHALLENGED_IP, `nonce=${nonce}&solution=${solve(nonce)}&to=%2Fcart`);
    expect(ok.status).toBe(302);
    expect(ok.headers.get('location')).toBe('/cart');
    expect(ok.headers.get('set-cookie')).toContain(`${CHALLENGE_COOKIE}=`);
    expect(events.some((e) => e.st === 200 && e.ch === 1)).toBe(true);

    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    const after = await call(a, '/cart', { headers: { 'cf-connecting-ip': CHALLENGED_IP, cookie, ...HTML } });
    expect(after.status).toBe(200);
  });

  it('challenges on a path rule, not just an ip', async () => {
    const a = await primed();
    const res = await call(a, '/admin/users', { headers: { 'cf-connecting-ip': '8.8.8.8', ...HTML } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-camada-challenge')).toBe('1');
  });

  it('answers 403 JSON for a non-HTML challenge', async () => {
    const a = await primed();
    const res = await call(a, '/checkout', { headers: { 'cf-connecting-ip': '8.8.8.8', accept: 'application/json' } });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'challenge_required' });
  });

  it('refuses an oversized verify body instead of buffering it', async () => {
    const a = await primed();
    const res = await postSolution(a, CHALLENGED_IP, `nonce=x&solution=1&to=%2F&pad=${'a'.repeat(5000)}`);
    expect(res.status).toBe(413);
  });

  it('rejects a forged nonce and sets no cookie', async () => {
    const a = await primed();
    const forged = 'a'.repeat(32);
    const res = await postSolution(a, CHALLENGED_IP, `nonce=${forged}&solution=${solve(forged)}&to=%2Fcart`);
    expect(res.status).toBe(403);
    expect(res.headers.get('set-cookie')).toBeNull();
  });

  it('never redirects off-site', async () => {
    const a = await primed();
    const page = await call(a, '/cart', { headers: { 'cf-connecting-ip': CHALLENGED_IP, ...HTML } });
    const nonce = nonceOf(await page.text());
    const res = await postSolution(a, CHALLENGED_IP, `nonce=${nonce}&solution=${solve(nonce)}&to=${encodeURIComponent('https://evil.test')}`);
    expect(res.headers.get('location')).toBe('/');
  });

  it('still blocks a blocked ip at the verify endpoint', async () => {
    const a = await primed();
    const res = await postSolution(a, BLOCKED_IP, 'nonce=x&solution=1&to=%2F');
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('ip4');
  });

  it('does nothing when challenge: false', async () => {
    const a = await primed({ challenge: false });
    expect((await call(a, '/cart', { headers: { 'cf-connecting-ip': CHALLENGED_IP, ...HTML } })).status).toBe(200);
  });
});

describe('trusting the client address', () => {
  it('ignores cf-connecting-ip off Workers, where any client can forge it', async () => {
    const a = await primed();
    // Same header, same blocked ip — but no `request.cf`, so this is node-server/Bun/Deno and
    // the header is attacker-controlled. Honouring it would be blocklist evasion, and would let
    // an attacker mint a `_cch` bound to any address they name.
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': BLOCKED_IP } }, null);
    expect(res.status).toBe(200);
  });

  it('still honours a trusted-proxy XFF off Workers', async () => {
    resetCamada();
    const a = new Hono();
    a.use('*', camada({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' }, fetchImpl }));
    a.get('/', (c) => c.text('home'));
    await call(a, '/', {}, null);
    await call(a, '/', {}, null);
    const res = await call(a, '/', { headers: { 'x-forwarded-for': BLOCKED_IP } }, null);
    expect(res.status).toBe(403);
  });
});

describe('per-configuration engines', () => {
  it('never lends one tenant\'s snapshot or ingest token to another mount', async () => {
    resetCamada();
    const other = { ...ENV, CAMADA_KEY: 'tok-other.snap-other' };
    const a = new Hono();
    a.use('*', camada({ env: ENV, fetchImpl }));
    a.get('/', (c) => c.text('a'));
    const b = new Hono();
    b.use('*', camada({ env: other, fetchImpl }));
    b.get('/', (c) => c.text('b'));

    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    await call(b, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    await call(b, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(tenantTokens).toContain('tok-acme');
    expect(tenantTokens).toContain('tok-other');   // app B must not ship under tenant A's token
  });

  it('does not go permanently inert after one unconfigured request', async () => {
    resetCamada();
    let env: Record<string, string | undefined> = {};
    const a = new Hono();
    a.use('*', camada({ get env() { return env; }, fetchImpl } as never));
    a.get('/', (c) => c.text('home'));
    await call(a, '/', { headers: { 'cf-connecting-ip': BLOCKED_IP } });   // no key: inert
    env = ENV;
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });    // keyed now: must wake up
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': BLOCKED_IP } });
    expect(res.status).toBe(403);
  });
});

describe('session', () => {
  it('mints the shared _sfp cookie so sid and ns are real at this tap', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(res.headers.get('set-cookie')).toContain('_sfp=');
    expect(res.headers.get('set-cookie')).toContain('HttpOnly');
  });

  it('never overwrites an existing session', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8', cookie: '_sfp=known-sid' } });
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(events.at(-1)).toMatchObject({ sid: 'known-sid' });
  });
});

describe('fail open', () => {
  it('is inert without a key and never touches the app', async () => {
    const a = new Hono();
    a.use('*', camada({ env: {}, fetchImpl }));
    a.get('/', (c) => c.text('home'));
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': BLOCKED_IP } });
    expect(res.status).toBe(200);
    expect(events).toEqual([]);
  });

  it('respects CAMADA_DISABLED=1', async () => {
    const a = new Hono();
    a.use('*', camada({ env: { ...ENV, CAMADA_DISABLED: '1' }, fetchImpl }));
    a.get('/', (c) => c.text('home'));
    expect((await call(a, '/', { headers: { 'cf-connecting-ip': BLOCKED_IP } })).status).toBe(200);
  });

  it('lets traffic through while the snapshot server is down', async () => {
    const dead: typeof fetch = (async () => { throw new Error('ECONNREFUSED'); }) as typeof fetch;
    const a = new Hono();
    a.use('*', camada({ env: ENV, fetchImpl: dead }));
    a.get('/', (c) => c.text('home'));
    expect((await call(a, '/', { headers: { 'cf-connecting-ip': BLOCKED_IP } })).status).toBe(200);
  });

  it('serves no challenge to a client it cannot identify', async () => {
    const a = await primed();
    // no cf-connecting-ip, no trusted proxy: ip resolves to null, so ip rules and the challenge
    // both stand down — but a path challenge still cannot mint an unbound cookie.
    const res = await call(a, '/admin/users', { headers: HTML });
    expect(res.status).toBe(200);
  });
});
