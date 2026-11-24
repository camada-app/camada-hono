import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { camada, resetCamada, track, type CamadaHonoOptions } from '../src/index.js';

const fixture = new URL('../node_modules/@camada/core/test/fixtures/blk3/', import.meta.url);
const meta = readFileSync(new URL('v4-basic.meta.json', fixture));
const bin = readFileSync(new URL('v4-basic.bin', fixture));
const frame = new ArrayBuffer(4 + meta.length + bin.length);
new DataView(frame).setUint32(0, meta.length, true);
new Uint8Array(frame).set(meta, 4);
new Uint8Array(frame).set(bin, 4 + meta.length);

const AUTH = { authorization: 'Bearer fake-token-0001-not-a-real-credential' };
const TK = 'b3a18c6c56d5a2f7ad636bf950a919d7';
const API_HEADERS = { ...AUTH, 'x-api-key': 'fake-api-key-0007' };
const API_TK = '94a6878c5d6bc3739f9a3d5644359a38';
const ENV = { CAMADA_KEY: 'ct_test_fixture_key.snap' };
const ON = { CAMADA_TOKEN_HASH: '1' };
const CHALLENGED = { 'cf-connecting-ip': '192.0.2.20', accept: 'text/html', ...AUTH };

function harness(options: CamadaHonoOptions = {}) {
  const events: Record<string, unknown>[] = [];
  const app = new Hono();
  app.use('*', camada({
    ...options,
    fetchImpl: async (url, init) => {
      if (String(url).endsWith('/snapshot')) return new Response(frame);
      events.push(...(JSON.parse(String(init?.body)) as typeof events));
      return new Response(null, { status: 202 });
    },
  }));
  app.get('/', (c) => {
    c.req.raw.headers.delete('authorization');   // the hash must read the original header before next()
    return c.text('ok');
  });
  app.get('/track', (c) => { void track(c, 'login_succeeded'); return c.text('ok'); });

  async function request(path: string, init?: RequestInit, env?: Record<string, string>) {
    const waits: Promise<unknown>[] = [];
    const req = new Request(`https://app.test${path}`, init);
    Object.assign(req, { cf: {} });
    const res = await app.request(req, undefined, { ...ENV, ...env }, {
      waitUntil(p) { waits.push(p); },
      passThroughOnException() {},
      props: {},
    });
    return { res, waits };
  }

  async function send(path: string, init?: RequestInit, env?: Record<string, string>) {
    const { res, waits } = await request(path, init, env);
    await Promise.all(waits);
    return res;
  }

  return { app, events, request, send };
}

afterEach(() => { vi.restoreAllMocks(); resetCamada(); });

describe('credential hash on shipped rows', () => {
  it.each([
    { name: 'off by default', options: {}, env: {} },
    { name: 'explicit false overrides c.env', options: { tokenHash: false }, env: ON },
  ])('$name', async ({ options, env }) => {
    const { send, events } = harness(options);
    const sign = vi.spyOn(crypto.subtle, 'sign');
    expect((await send('/', { headers: AUTH }, env)).status).toBe(200);
    expect(events).toHaveLength(1);
    expect(events[0]).not.toHaveProperty('tk');
    expect(sign).not.toHaveBeenCalled();
  });

  it('hashes the original Authorization credential on capture when opted in', async () => {
    const { send, events } = harness({ tokenHash: true });
    const res = await send('/', { headers: AUTH });
    expect(res.status).toBe(200);
    expect(events).toEqual([expect.objectContaining({ rid: res.headers.get('x-rid'), st: 200, tk: TK })]);
  });

  it('uses the current c.env flag and header on each request', async () => {
    const { send, events } = harness();
    const init = { headers: API_HEADERS };
    await send('/', init);
    await send('/', init, ON);
    await send('/', init, { ...ON, CAMADA_TOKEN_HEADER: 'x-api-key' });
    await send('/', init);
    expect(events.map((ev) => ev.tk)).toEqual([undefined, TK, API_TK, undefined]);
  });

  it('prefers the tokenHeader option over Authorization and the env header', async () => {
    const { send, events } = harness({ tokenHash: true, tokenHeader: 'x-api-key' });
    await send('/', { headers: API_HEADERS }, { CAMADA_TOKEN_HEADER: 'x-other' });
    expect(events).toEqual([expect.objectContaining({ tk: API_TK })]);
  });

  it('falls back to Authorization and warns once for an ignored header', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { send, events } = harness({ tokenHash: true, tokenHeader: 'cookie' });
    await send('/', { headers: AUTH });
    await send('/', { headers: AUTH });
    expect(events.map((ev) => ev.tk)).toEqual([TK, TK]);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('hashes block, challenge serve and successful verify rows', async () => {
    const { send, events } = harness({ tokenHash: true });
    await send('/');   // load the snapshot
    events.length = 0;
    const block = await send('/', { headers: { ...AUTH, 'cf-connecting-ip': '203.0.113.66' } });
    expect(block.status).toBe(403);
    const page = await send('/', { headers: CHALLENGED });
    expect(page.status).toBe(403);
    const nonce = /name="nonce" value="([0-9a-f]{32})"/.exec(await page.text())![1];
    let solution = 0;
    while (!createHash('sha256').update(`${nonce}.${solution}`).digest('hex').startsWith('0000')) solution++;
    const verify = await send('/__camada/challenge', {
      method: 'POST', headers: CHALLENGED, body: new URLSearchParams({ nonce, solution: String(solution), to: '/' }),
    });
    expect(verify.status).toBe(302);
    expect(events).toEqual([
      expect.objectContaining({ st: 403, blk: 'ip4', tk: TK }),
      expect.objectContaining({ st: 403, blk: 'challenge', tk: TK }),
      expect.objectContaining({ st: 200, ch: 1, tk: TK }),
    ]);
  });

  it('serves and ships a scheme-only header without tk', async () => {
    const { send, events } = harness({ tokenHash: true });
    expect((await send('/', { headers: { authorization: 'Bearer' } })).status).toBe(200);
    expect(events).toEqual([expect.objectContaining({ st: 200 })]);
    expect(events[0]).not.toHaveProperty('tk');
  });

  it('serves and ships without tk when signing fails', async () => {
    const sign = vi.spyOn(crypto.subtle, 'sign').mockRejectedValueOnce(new Error('sign failed'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const { send, events } = harness({ tokenHash: true });
    const res = await send('/', { headers: AUTH });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
    expect(sign).toHaveBeenCalledTimes(1);
    expect(events).toEqual([expect.objectContaining({ st: 200 })]);
    expect(events[0]).not.toHaveProperty('tk');
  });

  it('holds a pending capture hash and its flush through waitUntil', async () => {
    const { send, request, events } = harness({ tokenHash: true });
    await send('/');   // keep the snapshot poll out of this request's waitUntil calls
    events.length = 0;
    const sign = crypto.subtle.sign.bind(crypto.subtle);
    let resume!: () => void;
    const pending = new Promise<void>((resolve) => { resume = resolve; });
    vi.spyOn(crypto.subtle, 'sign').mockImplementationOnce(async (...args) => {
      await pending;
      return sign(...args);
    });
    const { res, waits } = await request('/', { headers: AUTH });
    try {
      expect(res.status).toBe(200);
      expect(events).toHaveLength(0);
      expect(waits).toHaveLength(1);
    } finally {
      resume();
    }
    await Promise.all(waits);
    expect(events).toEqual([expect.objectContaining({ st: 200, tk: TK })]);
  });

  it('starts the hashed POST before returning on Lambda without waitUntil', async () => {
    const { app, events } = harness({ tokenHash: true });
    const sign = crypto.subtle.sign.bind(crypto.subtle);
    let resume!: () => void;
    const pending = new Promise<void>((resolve) => { resume = resolve; });
    const signing = vi.spyOn(crypto.subtle, 'sign').mockImplementationOnce(async (...args) => {
      await pending;
      return sign(...args);
    });
    const responding = app.request('/', { headers: AUTH }, { ...ENV, AWS_LAMBDA_FUNCTION_NAME: 'test-function' });
    try {
      await vi.waitFor(() => expect(signing).toHaveBeenCalledOnce());
      resume();
      expect((await responding).status).toBe(200);
      expect(events).toEqual([expect.objectContaining({ st: 200, tk: TK })]);
    } finally {
      resume();
    }
  });

  it('relays a beacon without forged tk, bf or upf', async () => {
    const { send, events } = harness({ tokenHash: true });
    const res = await send('/_cam/fp', {
      method: 'POST', headers: AUTH, body: JSON.stringify({ rid: 'abc', tk: TK, bf: ['user'], upf: ['file'] }),
    });
    expect(res.status).toBe(204);
    expect(events).toEqual([expect.objectContaining({ sig: 1, rid: 'abc' })]);
    for (const key of ['tk', 'bf', 'upf']) expect(events[0]).not.toHaveProperty(key);
  });

  it('keeps tk on the request row when a handler also sends a track row', async () => {
    const { send, events } = harness({ tokenHash: true });
    await send('/track', { headers: AUTH });
    expect(events.find((ev) => ev.p === '/track')).toMatchObject({ tk: TK });
    const outcome = events.find((ev) => ev.et === 'login_succeeded');
    expect(outcome).toBeDefined();
    expect(outcome).not.toHaveProperty('tk');
  });
});
