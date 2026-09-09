// @camada/hono against the golden v4 and v5 snapshots, driven through a real Hono app with
// app.request(). The fixtures are read through the file: symlink to @camada/core, so this
// package is pinned to the same bytes edge-analyst generates.
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Hono } from 'hono';
import { CHALLENGE_COOKIE } from '@camada/core';
import iife from '@camada/browser/iife-string';
import { camada, resetCamada, track, scriptTag, type CamadaHonoOptions } from '../src/index.js';

const FIX = fileURLToPath(new URL('../node_modules/@camada/core/test/fixtures/blk3/', import.meta.url));
const FIX5 = fileURLToPath(new URL('../node_modules/@camada/core/test/fixtures/blk5/', import.meta.url));
const container = (dir: string, name: string) => ({
  bin: readFileSync(dir + name + '.bin'),
  meta: JSON.stringify(JSON.parse(readFileSync(dir + name + '.meta.json', 'utf8'))),
});
const V4 = container(FIX, 'v4-basic');
const V5 = container(FIX5, 'v5-rules');
// Which container this tenant published. §D3: the client always asks for the newest it can
// read and the server answers with what it has, so the two are set independently here.
let served = V4;

const BLOCKED_IP = '203.0.113.66';     // block side
const CHALLENGED_IP = '192.0.2.20';    // challenge side only
const ALLOWED_IP = '10.0.0.7';         // allow-listed inside the blocked 10.0.0.0/8
const HTML = { accept: 'text/html', 'sec-fetch-dest': 'document' };
// v5-rules only: the ordered custom rules the golden container carries.
const RULE_BLOCKED_IP = '198.51.100.7';   // builtin:block, a manual-block entry
const SKIP_PATH = '/healthz';             // cr_00000000000a, skip — beats every side
const WARN_UA = 'Scrapy/2.11 (+https://scrapy.org)';   // cr_00000000000e, warn
const BLOCKED_UA = 'curl/8.4.0';                       // cr_00000000000f, block
const BLOCKED_HEADER = 'x-api-key';                    // cr_000000000019, `header is` → block
const BLOCKED_HEADER_VALUE = 'leaked-key-1';

const BASE_CONFIG = { tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 };
let CONFIG = BASE_CONFIG;   // one test serves `beacon: false`; reset in beforeEach
const ENV = { CAMADA_KEY: 'tok-acme.snap-acme', CAMADA_INGEST_URL: 'http://analyst.test', CAMADA_SNAPSHOT_URL: 'http://analyst.test/snapshot' };

// 200 body frame: [u32 LE meta-length][meta JSON][BLK bin]
function frame(): ArrayBuffer {
  const m = new TextEncoder().encode(served.meta);
  const f = new Uint8Array(4 + m.length + served.bin.length);
  new DataView(f.buffer).setUint32(0, m.length, true);
  f.set(m, 4); f.set(new Uint8Array(served.bin), 4 + m.length);
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
    return new Response(frame(), { status: 200, headers: { etag: `"${JSON.parse(served.meta).version}"`, 'x-camada-config': JSON.stringify(CONFIG) } });
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
  a.get('/healthz', (c) => c.text('ok'));
  a.get('/api/v2/dump', (c) => c.text('dump'));
  a.get('/missing-route-is-404', (c) => c.notFound());
  a.get('/page', (c) => c.html(`<html><head>${scriptTag(c)}</head><body>page</body></html>`));
  a.post('/login', async (c) => { await track(c, 'login_failed', { user: 'alice@example.com' }); return c.text('no', 401); });
  a.post('/signup', (c) => { void track(c, 'signup'); return c.text('ok'); });   // fire-and-forget: waitUntil must carry it
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

/** The same, against a tenant that publishes the v5 container (the ordered custom rules). */
async function primedV5(opts: CamadaHonoOptions = {}): Promise<Hono> {
  served = V5;
  return primed(opts);
}

const nonceOf = (page: string) => /name="nonce" value="([0-9a-f]{32})"/.exec(page)![1];
const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};

beforeEach(() => { events = []; sdkHeaders = []; snapshotVersions = []; tenantTokens = []; served = V4; CONFIG = BASE_CONFIG; resetCamada(); });

const ridOf = (html: string): string => /\?r=([0-9a-f-]{36})"/.exec(html)![1];
const postBeacon = (a: Hono, body: string, ip = '9.9.9.9', path = '/_cam/fp'): Promise<Response> =>
  call(a, path, { method: 'POST', headers: { 'cf-connecting-ip': ip, 'content-type': 'application/json' }, body });

describe('capture', () => {
  it('lets an unlisted request through and ships the event with the real status', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(res.status).toBe(200);
    expect(events.some((e) => e.tap === 'sdk-hono' && e.p === '/' && e.st === 200)).toBe(true);
  });

  it('reports its identity on every batch and asks for the newest snapshot', async () => {
    const a = await primed();
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(snapshotVersions[0]).toBe('5');   // §D3: this tenant only has v4, and is answered with it
    expect(sdkHeaders.length).toBeGreaterThan(0);
    expect(sdkHeaders.every((h) => /^@camada\/hono\/\d+\.\d+\.\d+$/.test(h))).toBe(true);
  });

  it('pins the container when the app asks for v4', async () => {
    const a = await primed({ snapshotVersion: 4 });
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(snapshotVersions[0]).toBe('4');
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

describe('ordered custom rules (v5)', () => {
  it('lets a skip rule beat the wider block below it', async () => {
    const a = await primedV5();
    expect((await call(a, SKIP_PATH, { headers: { 'cf-connecting-ip': BLOCKED_IP } })).status).toBe(200);
    expect((await call(a, '/', { headers: { 'cf-connecting-ip': BLOCKED_IP } })).status).toBe(403);
  });

  it('lets the built-in Allow-list rule beat the wider block below it', async () => {
    const a = await primedV5();
    expect((await call(a, '/', { headers: { 'cf-connecting-ip': ALLOWED_IP } })).status).toBe(200);
    expect(events.at(-1)!.wrn).toBeUndefined();   // an allowed request is an ordinary request
  });

  it('blocks by rule with x-block-rule and ships blk rule + rl', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': RULE_BLOCKED_IP } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('rule');
    expect(res.headers.get('x-block-rule')).toBe('builtin:block');
    expect(res.headers.get('x-block-version')).toBeTruthy();
    expect(events.some((e) => e.st === 403 && e.blk === 'rule' && e.rl === 'builtin:block')).toBe(true);
  });

  it('blocks by a user-agent rule — the tap must pass ua through', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8', 'user-agent': BLOCKED_UA } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-rule')).toBe('cr_00000000000f');
  });

  it('blocks by a header rule — the tap must pass a header getter through', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8', [BLOCKED_HEADER]: BLOCKED_HEADER_VALUE } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('rule');
    expect(res.headers.get('x-block-rule')).toBe('cr_000000000019');
    expect(events.some((e) => e.st === 403 && e.blk === 'rule' && e.rl === 'cr_000000000019')).toBe(true);
  });

  it('matches a header rule however the client spelled the name', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8', 'X-API-Key': BLOCKED_HEADER_VALUE } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-rule')).toBe('cr_000000000019');
  });

  it('passes when the header the rule reads is absent', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(res.status).toBe(200);   // a condition the request cannot answer is false, negatives included
    const ev = events.at(-1)!;
    expect(ev.blk).toBeUndefined();
    expect(ev.rl).toBeUndefined();
  });

  it('blocks by an asn + country rule, which a bare Node tap cannot judge', async () => {
    const a = await primedV5();
    const res = await callWithCf(a, { asn: 64500, country: 'FR' }, { 'cf-connecting-ip': '8.8.8.8' });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-rule')).toBe('cr_000000000010');
  });

  it('serves the challenge page for a challenge rule', async () => {
    const a = await primedV5();
    const res = await call(a, '/checkout', { headers: { 'cf-connecting-ip': '8.8.8.8', ...HTML } }, { country: 'DE' });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-camada-challenge')).toBe('1');
    expect(events.some((e) => e.st === 403 && e.blk === 'challenge')).toBe(true);
  });

  it('passes a warn rule and stamps wrn on the event', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8', 'user-agent': WARN_UA } });
    expect(res.status).toBe(200);
    const ev = events.at(-1)!;
    expect(ev.wrn).toBe('cr_00000000000e');
    expect(ev.blk).toBeUndefined();   // warn is not a block: the traffic passed
  });

  it('leaves an unmatched request alone', async () => {
    const a = await primedV5();
    expect((await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8', 'user-agent': 'Mozilla/5.0' } })).status).toBe(200);
    const ev = events.at(-1)!;
    expect(ev.wrn).toBeUndefined();
    expect(ev.rl).toBeUndefined();
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

describe('first-party beacon', () => {
  it('serves the IIFE at /_cam/b.js and ships nothing for it', async () => {
    const a = await primed();
    const res = await call(a, '/_cam/b.js?r=abc', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('javascript');
    expect(res.headers.get('cache-control')).toBe('public, max-age=3600');
    expect(await res.text()).toBe(iife);
    expect(events).toEqual([]);
  });

  it('relays /_cam/fp as a sig:1 row with the server-resolved ip and tap', async () => {
    const a = await primed();
    const res = await postBeacon(a, JSON.stringify({ rid: 'abc', tz: 'UTC', ip: '1.1.1.1', tap: 'proxy' }));
    expect(res.status).toBe(204);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ sig: 1, rid: 'abc', tz: 'UTC', ip: '9.9.9.9', tap: 'sdk-hono' });
    expect(events[0].st).toBeUndefined();
  });

  it('joins the beacon to the page event on rid', async () => {
    const a = await primed();
    const html = await (await call(a, '/page', { headers: { 'cf-connecting-ip': '8.8.8.8' } })).text();
    const rid = ridOf(html);
    expect(events.find((e) => e.p === '/page')).toMatchObject({ rid, tap: 'sdk-hono' });
    await postBeacon(a, JSON.stringify({ rid, tz: 'UTC' }), '8.8.8.8');
    expect(events.find((e) => e.sig === 1)).toMatchObject({ rid, ip: '8.8.8.8' });
  });

  it('drops a body that is not a beacon', async () => {
    const a = await primed();
    expect((await postBeacon(a, 'not-json')).status).toBe(204);
    expect((await postBeacon(a, '[1,2]')).status).toBe(204);
    expect(events).toEqual([]);
  });

  it('rejects an oversized beacon', async () => {
    const a = await primed();
    expect((await postBeacon(a, 'x'.repeat(80 * 1024))).status).toBe(413);
    // The declared length is checked before the body is read: a client announcing 64 KB is refused unread.
    const declared = await call(a, '/_cam/fp', {
      method: 'POST', headers: { 'cf-connecting-ip': '9.9.9.9', 'content-type': 'application/json', 'content-length': String(64 * 1024) }, body: '{"rid":"abc"}',
    });
    expect(declared.status).toBe(413);
    expect(events).toEqual([]);
  });

  it('still blocks a blocked client at both endpoints', async () => {
    const a = await primed();
    const script = await call(a, '/_cam/b.js', { headers: { 'cf-connecting-ip': BLOCKED_IP } });
    expect(script.status).toBe(403);
    expect(script.headers.get('x-block-reason')).toBe('ip4');
    const fp = await postBeacon(a, JSON.stringify({ rid: 'abc' }), BLOCKED_IP);
    expect(fp.status).toBe(403);
    expect(events).toHaveLength(2);
    expect(events.every((e) => e.blk === 'ip4' && e.sig === undefined)).toBe(true);
  });

  it('serves nothing when the tenant disabled the beacon', async () => {
    CONFIG = { ...BASE_CONFIG, beacon: false };
    const a = await primed();
    expect((await call(a, '/_cam/b.js', { headers: { 'cf-connecting-ip': '8.8.8.8' } })).status).toBe(404);
    expect((await postBeacon(a, JSON.stringify({ rid: 'abc' }))).status).toBe(404);   // falls through to the app, as @camada/node does
    expect(events.some((e) => e.sig === 1)).toBe(false);
    const html = await (await call(a, '/page', { headers: { 'cf-connecting-ip': '8.8.8.8' } })).text();
    expect(html).not.toContain('<script');
  });

  it('honours scriptPath and fpPath', async () => {
    const a = await primed({ scriptPath: '/api/cam/b.js', fpPath: '/api/cam/fp' });
    const html = await (await call(a, '/page', { headers: { 'cf-connecting-ip': '8.8.8.8' } })).text();
    expect(html).toContain('<script src="/api/cam/b.js?r=');
    expect((await call(a, '/api/cam/b.js', { headers: { 'cf-connecting-ip': '8.8.8.8' } })).status).toBe(200);
    expect((await call(a, '/_cam/b.js', { headers: { 'cf-connecting-ip': '8.8.8.8' } })).status).toBe(404);
    events.length = 0;
    expect((await postBeacon(a, JSON.stringify({ rid: 'abc' }), '9.9.9.9', '/api/cam/fp')).status).toBe(204);
    expect(events[0]).toMatchObject({ sig: 1, rid: 'abc' });
  });

  it('emits no tag where the middleware did not run', async () => {
    const bare = new Hono();
    bare.get('/page', (c) => c.html(`<head>${scriptTag(c)}</head>`));
    expect(await (await call(bare, '/page')).text()).toBe('<head></head>');
    const off = new Hono();
    off.use('*', camada({ env: { ...ENV, CAMADA_DISABLED: '1' }, fetchImpl }));
    off.get('/page', (c) => c.html(`<head>${scriptTag(c)}</head>`));
    expect(await (await call(off, '/page')).text()).toBe('<head></head>');
  });
});

describe('track', () => {
  it('ships an app-context event joined to the request, with the user hashed', async () => {
    const a = await primed();
    const res = await call(a, '/login', { method: 'POST', headers: { 'cf-connecting-ip': '8.8.8.8', cookie: '_sfp=known-sid' } });
    expect(res.status).toBe(401);
    const row = events.find((e) => e.et === 'login_failed')!;
    expect(row).toMatchObject({ tap: 'sdk-hono', sid: 'known-sid', ip: '8.8.8.8' });
    expect(row.uid).toMatch(/^[0-9a-f]{32}$/);
    expect(typeof row.ts).toBe('number');
    expect(row.p).toBeUndefined();
    expect(row.st).toBeUndefined();
    expect(row.rid).toBe(events.find((e) => e.p === '/login')!.rid);
    expect(JSON.stringify(events)).not.toContain('alice');
  });

  it('uses the session it just minted on a first visit', async () => {
    const a = await primed();
    const res = await call(a, '/login', { method: 'POST', headers: { 'cf-connecting-ip': '8.8.8.8' } });
    const sid = /_sfp=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')![1];
    expect(events.find((e) => e.et === 'login_failed')).toMatchObject({ sid });
    expect(events.find((e) => e.p === '/login')).toMatchObject({ sid, ns: 1 });
  });

  it('carries a fire-and-forget call through waitUntil, uid null without a user', async () => {
    const a = await primed();
    expect((await call(a, '/signup', { method: 'POST', headers: { 'cf-connecting-ip': '8.8.8.8' } })).status).toBe(200);
    expect(events.find((e) => e.et === 'signup')).toMatchObject({ uid: null, tap: 'sdk-hono' });
  });

  it('is a silent no-op where the middleware did not run', async () => {
    const route = (h: Hono) => h.post('/login', async (c) => { expect(await track(c, 'login_failed', { user: 'x' })).toBeUndefined(); return c.text('ok'); });
    const bare = route(new Hono());
    expect((await call(bare, '/login', { method: 'POST' })).status).toBe(200);
    const off = new Hono(); off.use('*', camada({ env: { ...ENV, CAMADA_DISABLED: '1' }, fetchImpl })); route(off);
    expect((await call(off, '/login', { method: 'POST' })).status).toBe(200);
    const unkeyed = new Hono(); unkeyed.use('*', camada({ env: {}, fetchImpl })); route(unkeyed);
    expect((await call(unkeyed, '/login', { method: 'POST' })).status).toBe(200);
    expect(events).toEqual([]);
  });

  it('never throws while ingest is down', async () => {
    const dead: typeof fetch = (async () => { throw new Error('ECONNREFUSED'); }) as typeof fetch;
    const a = new Hono();
    a.use('*', camada({ env: ENV, fetchImpl: dead }));
    a.post('/login', async (c) => { await track(c, 'login_failed', { user: 'alice' }); return c.text('no', 401); });
    expect((await call(a, '/login', { method: 'POST', headers: { 'cf-connecting-ip': '8.8.8.8' } })).status).toBe(401);
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
