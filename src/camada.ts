// @camada/hono — the Hono middleware for Cloudflare Workers (SEC-07, D33).
//   app.use('*', camada());
// Workers-native: `cf-connecting-ip` for the client address, `request.cf` for asn / country /
// TLS fingerprint (so ASN and country rules really enforce at this tap), and
// `c.executionCtx.waitUntil` so the snapshot poll and the event flush outlive the response.
// Everything runs inside camada's fail-open envelope: a camada bug, a dead ingest or a corrupt
// snapshot costs telemetry, never the app's response.
import type { Context, MiddlewareHandler, Next } from 'hono';
import iife from '@camada/browser/iife-string';
import {
  SnapshotClient, EventQueue, buildWireEvent, resolveClientIp, logRateLimited, guardedAsync, onBodyDone,
  guarded, createChallengeAsync, challengePage, challengeCookie, safeReturnTo, wantsHtml, parseFormBody,
  CHALLENGE_COOKIE, DEFAULT_SNAPSHOT_VERSION, TAP_HONO,
  type AsyncChallengeKit, type TrustedProxyConfig, type WireEvent,
} from '@camada/core';
import { resolveEnv, type CamadaHonoOptions, type ResolvedEnv } from './env.js';
import { VAR, beaconEnabled, type CamadaVars } from './context.js';
import { SDK_ID } from './version.js';

const DEFAULT_CHALLENGE_PATH = '/__camada/challenge';
const SCRIPT_PATH = '/_cam/b.js';   // the beacon IIFE; its auto-init posts to the sibling `fp` and reads the rid from ?r=
const FP_PATH = '/_cam/fp';
const FP_MAX = 32 * 1024;        // matches the analyst's /fp cap: never accept what ingest will 413
const SESSION_COOKIE = '_sfp';   // the same session cookie as every other tap: sid/ns stay comparable
const SESSION_MAX_AGE = 2592000;
const BODY_MAX = 4 * 1024;       // the verify form is ~120 bytes; anything larger is not ours
const encoder = new TextEncoder();

export interface Engine {
  env: ResolvedEnv;
  snap: SnapshotClient;
  queue: EventQueue;
  kit: AsyncChallengeKit;
}

export type WaitUntil = (p: Promise<unknown>) => void;

// One engine per resolved configuration, not per module: a Workers isolate can host several
// Hono apps, and a shared singleton would enforce the first tenant's snapshot on the second
// and sign its `_cch` cookies with the first tenant's secret. An unconfigured request is never
// cached — a warm-up or a differently-keyed mount must not leave the isolate inert for good.
const engines = new Map<string, Engine>();

/** Test/reset hook: drops every cached engine. */
export function resetCamada(): void {
  for (const e of engines.values()) { e.snap.stop(); e.queue.stop(); }
  engines.clear();
}

function ensure(opts: CamadaHonoOptions, ctxEnv: Record<string, string | undefined>): Engine | null {
  const env = resolveEnv(opts, ctxEnv);
  if (!env) {
    logRateLimited(new Error('CAMADA_KEY not set — camada is inactive'));
    return null;
  }
  const snapshotVersion = opts.snapshotVersion ?? DEFAULT_SNAPSHOT_VERSION;
  const id = `${env.ingestToken}|${env.ingestUrl}|${env.snapshotUrl}|${snapshotVersion}`;
  const cached = engines.get(id);
  if (cached) return cached;
  const injected = opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {};   // never pass an explicit undefined key
  const engine: Engine = {
    env,
    snap: new SnapshotClient({
      url: env.snapshotUrl, token: env.snapToken, mode: 'lazy', sdk: SDK_ID,
      snapshotVersion, ...injected,
    }),
    queue: new EventQueue({ url: env.ingestUrl, token: env.ingestToken, sdk: SDK_ID, ...injected }),
    kit: createChallengeAsync({ secret: env.secret }),
  };
  engines.set(id, engine);
  return engine;
}

const cookieValue = (cookie: string, name: string): string | null => {
  const src = '; ' + cookie;
  const i = src.indexOf('; ' + name + '=');
  if (i === -1) return null;
  const start = i + name.length + 3;
  const j = src.indexOf(';', start);
  return src.slice(start, j === -1 ? undefined : j);
};

interface CfProps { asn?: number; country?: string; tlsClientExtensionsSha1?: string; httpProtocol?: string }
const cfOf = (req: Request): CfProps => ((req as Request & { cf?: CfProps }).cf ?? {});

const trustedProxy = (e: Engine): TrustedProxyConfig | null =>
  e.env.trustedProxy ?? e.snap.config?.trusted_proxy ?? null;

/** Cloudflare sets `cf-connecting-ip` itself and a client cannot forge it — but only on
 *  Workers, which is also the only place `request.cf` exists. On any other Hono runtime
 *  (node-server, Bun, Deno) that header is attacker-controlled, so it is ignored there and the
 *  trusted-proxy rules decide, exactly as they do for X-Forwarded-For. */
const clientIp = (e: Engine, req: Request): string | null => {
  const cf = (req as Request & { cf?: unknown }).cf;
  const direct = cf ? req.headers.get('cf-connecting-ip') : null;
  return direct || resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(e));
};

interface RequestFacts {
  url: URL;
  path: string;
  cf: CfProps;
  ip: string | null;
  sid: string | null;
}

function describeRequest(e: Engine, req: Request): RequestFacts {
  const url = new URL(req.url);
  const cookies = req.headers.get('cookie') || '';
  return { url, path: url.pathname, cf: cfOf(req), ip: clientIp(e, req), sid: cookieValue(cookies, SESSION_COOKIE) };
}

function buildEvent(
  req: Request, path: string, query: string, ip: string | null, sid: string | null,
  rid: string = crypto.randomUUID(), newSession = false,   // the capture path passes the ids it shared with the app; camada's own answers need none
): WireEvent {
  const headers: Array<[string, string]> = [];
  req.headers.forEach((v, k) => headers.push([k, v]));   // workerd normalises header order: no HEADER_ORDER signal here
  const cf = cfOf(req);
  const ev = buildWireEvent(
    {
      method: req.method, host: req.headers.get('host') ?? new URL(req.url).host, path, query, headers, ip,
      // The client's connection terminates at Cloudflare, so `cf.httpProtocol` really is the
      // visitor's protocol (ea's TAP_CAPS grants this tap TRUE_PROTO on that basis). Never read
      // a forwarded header for this — that would be the proxy's hop, not the client's.
      httpVersion: cf.httpProtocol ? cf.httpProtocol.replace(/^HTTP\//i, '') : null,
    },
    { tap: TAP_HONO, rid, sid, newSession },
  );
  if (cf.asn) ev.asn = cf.asn;
  if (cf.country) ev.cc = cf.country;
  if (cf.tlsClientExtensionsSha1) ev.tlsx = cf.tlsClientExtensionsSha1;
  return ev;
}

/** Push then flush through `waitUntil` — the one rule every row (wire event, beacon, track()) follows. */
export function ship(e: Engine, ev: unknown, waitUntil: WaitUntil): void {
  e.queue.push(ev);
  e.queue.flush(waitUntil);
}

/** 204 and a `sig: 1` row on the event batch — one request per flush at the analyst, not one per page view. */
async function relayBeacon(eng: Engine, req: Request, ip: string | null, waitUntil: WaitUntil): Promise<Response> {
  const noContent = () => new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
  if (Number(req.headers.get('content-length')) > FP_MAX) return new Response(null, { status: 413 });
  const body = await req.text();
  if (encoder.encode(body).byteLength > FP_MAX) return new Response(null, { status: 413 });
  let parsed: unknown;
  try { parsed = JSON.parse(body); } catch { return noContent(); }   // not a beacon: drop it, never ship junk
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return noContent();
  // Spread first: the ip and the tap are the server's to say, whatever the body claimed.
  ship(eng, { ...(parsed as Record<string, unknown>), sig: 1, ip, tap: TAP_HONO }, waitUntil);
  return noContent();
}

export function camada(opts: CamadaHonoOptions = {}): MiddlewareHandler {
  const challengePath = opts.challengePath ?? DEFAULT_CHALLENGE_PATH;
  const scriptPath = opts.scriptPath ?? SCRIPT_PATH;
  const fpPath = opts.fpPath ?? FP_PATH;

  return async function camadaHono(c: Context, next: Next): Promise<Response | void> {
    const t0 = Date.now();   // request start; the response event ships dur = settle - t0 (ms), @camada/node's semantics
    // Reading c.env and building the engine are inside the guard too: a Workers env carries
    // non-string bindings, and a throw here would 5xx the app on its very first request.
    const env = guarded(() => ({ ...(c.env as Record<string, string | undefined> | undefined), ...opts.env }), {} as Record<string, string | undefined>);
    const eng = guarded(() => (env.CAMADA_DISABLED === '1' ? null : ensure(opts, env)), null);
    if (!eng) return next();
    // Same opt-out as @camada/next: the code option, or CAMADA_CHALLENGE=0 in the Worker env.
    const challengeOn = opts.challenge !== false && env.CAMADA_CHALLENGE !== '0';

    const waitUntil: WaitUntil = (p) => {
      try { c.executionCtx?.waitUntil(p); } catch { /* no execution context outside a fetch handler */ }
    };

    // The id of the `warn` rule that let this request through, read again after next() when the
    // response event is built (§D3). Every other action settles before the app ever runs.
    let warnRule: string | null = null;
    // Set on the capture path only: the ids this request shares with the app (scriptTag, track)
    // and with its own post-response event. Null when camada answered the request itself.
    let vars: CamadaVars | null = null;
    let newSession = false;

    const answer = await guardedAsync(async (): Promise<Response | null> => {
      eng.snap.ensureFresh(waitUntil);

      const req = c.req.raw;
      const { url, path, cf, ip, sid } = describeRequest(eng, req);

      const v = eng.snap.verdict({
        ip, path, ua: req.headers.get('user-agent'),   // §D3: without ua every `ua` rule is false
        // `header` conditions read the request through this getter; `Headers.get` is
        // case-insensitive, so the lower-cased name the matcher asks with finds whatever
        // spelling the client sent. Without it every `header` rule is false.
        header: (n) => req.headers.get(n),
        asn: cf.asn ?? null, country: cf.country ?? null, tlsx: cf.tlsClientExtensionsSha1 ?? null,
      });
      warnRule = v.warn ? v.rule ?? null : null;

      if (v.block) {
        const ev = buildEvent(req, path, url.search, ip, sid);
        ev.st = 403;
        ev.blk = v.reason;   // SDK-01: the analyst counts SDK blocks apart from the app's own 403s ('rule' when a rule decided)
        if (v.rule) ev.rl = v.rule;
        ship(eng, ev, waitUntil);
        const headers: Record<string, string> = {
          'content-type': 'text/plain', 'x-block-reason': String(v.reason ?? ''), 'x-block-version': v.version ?? '',
        };
        if (v.rule) headers['x-block-rule'] = v.rule;   // a custom rule blocked: name it, so the customer knows which row to edit
        return new Response('Forbidden', { status: 403, headers });
      }

      // A challenge needs a resolved client ip: the nonce and the `_cch` cookie are bound to it.
      // Without one, fail open rather than mint a cookie every unidentified client could use.
      if (challengeOn && ip) {
        // The verify endpoint answers first — a challenged client must be able to reach it.
        if (req.method === 'POST' && path === challengePath) return verify(eng, req, ip, sid, challengePath, waitUntil);
        const token = cookieValue(req.headers.get('cookie') || '', CHALLENGE_COOKIE);
        if (v.challenge && !(await eng.kit.tokenValid(ip, Date.now(), token))) {
          return serve(eng, req, ip, sid, challengePath, path + url.search, waitUntil);
        }
      }

      // The beacon endpoints come after enforcement (a blocked or challenged client gets neither
      // the script nor a relay) and before the app (they are camada's, not its) — @camada/node's order.
      if (beaconEnabled(eng)) {
        if (req.method === 'GET' && path === scriptPath) {
          return new Response(iife, { status: 200, headers: { 'content-type': 'application/javascript', 'cache-control': 'public, max-age=3600' } });
        }
        if (req.method === 'POST' && path === fpPath) return relayBeacon(eng, req, ip, waitUntil);
      }

      // Capture: mint the ids the app, the beacon and the post-response event all share. The
      // session is decided here rather than after next() so track() inside the handler and the
      // event both carry the sid a first visit is about to be given.
      newSession = !sid;
      vars = { eng, rid: crypto.randomUUID(), sid: sid ?? crypto.randomUUID(), ip, waitUntil, scriptPath };
      c.set(VAR, vars);
      return null;
    }, null);

    if (answer) return answer;

    await next();

    // Mint the shared session cookie the other taps use, so `sid`/`ns` are real here too
    // (ea's capability mask for sdk-hono claims SESSION). Never overwrite an existing one.
    guarded(() => {
      if (!vars || !newSession) return;
      const secure = new URL(c.req.raw.url).protocol === 'https:' ? '; Secure' : '';
      c.res.headers.append('set-cookie', `${SESSION_COOKIE}=${vars.sid}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; SameSite=Lax${secure}`);
    }, undefined);

    // The handler has answered, so this tap ships the real status — unlike @camada/next's
    // middleware position, which can only report pre-response. It ships once the body has gone
    // out (or the client left), so dur covers a streamed body, not just its first byte. waitUntil
    // holds the isolate until then: workerd stops pumping a body the client abandoned otherwise.
    const status = c.res.status;
    const shipEvent = () => void guardedAsync(async () => {
      const req = c.req.raw;
      const { url, path, ip } = describeRequest(eng, req);
      const cfg = eng.snap.config;
      if ((cfg?.exclude || []).some((x) => path.startsWith(x))) return;
      if (Math.random() >= (cfg?.sample ?? 1)) return;
      // `vars` is null only when the guard above threw before setting it — then the event still ships, with fresh ids.
      const ev = buildEvent(req, path, url.search, ip, vars?.sid ?? null, vars?.rid, newSession);
      ev.st = status;
      ev.dur = Math.max(0, Date.now() - t0);
      if (warnRule) ev.wrn = warnRule;   // §D3: the warn rule that let this request through
      ship(eng, ev, waitUntil);
    }, undefined);
    try {
      c.res = onBodyDone(c.res, shipEvent, { method: c.req.raw.method, waitUntil });
    } catch (err) {
      logRateLimited(err);   // a locked or foreign body: ship now (time to first byte), the response untouched
      shipEvent();
    }
  };
}

/** 403 + the proof-of-work page (HTML navigations) or 403 JSON, plus the `blk: "challenge"` event. */
async function serve(eng: Engine, req: Request, ip: string, sid: string | null, action: string, target: string, waitUntil: WaitUntil): Promise<Response> {
  const url = new URL(req.url);
  const ev = buildEvent(req, url.pathname, url.search, ip, sid);
  ev.st = 403;
  ev.blk = 'challenge';
  ship(eng, ev, waitUntil);

  if (!wantsHtml(req.headers.get('accept'), req.headers.get('sec-fetch-dest'))) {
    return new Response('{"error":"challenge_required"}', {
      status: 403,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' },
    });
  }
  const html = challengePage({ nonce: await eng.kit.nonce(ip, Date.now()), action, to: safeReturnTo(target) });
  return new Response(html, {
    status: 403,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1' },
  });
}

/** POST from the page: validate, set `_cch`, 302 back, ship `{ st: 200, ch: 1 }`. */
async function verify(eng: Engine, req: Request, ip: string, sid: string | null, action: string, waitUntil: WaitUntil): Promise<Response> {
  const url = new URL(req.url);
  // camada answers this path before the app runs, so it must not become a place to post
  // hundreds of megabytes at an unauthenticated endpoint.
  if (Number(req.headers.get('content-length')) > BODY_MAX) return new Response(null, { status: 413 });
  const body = await req.text();
  if (body.length > BODY_MAX) return new Response(null, { status: 413 });
  const form = parseFormBody(body);
  const to = safeReturnTo(form.to);
  const now = Date.now();
  if (!(await eng.kit.verify(ip, now, form.nonce, form.solution))) {
    const html = challengePage({ nonce: await eng.kit.nonce(ip, now), action, to });
    return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
  }
  const ev = buildEvent(req, url.pathname, '', ip, sid);
  ev.st = 200;
  ev.ch = 1;   // challenge passed (contract §A3 ingest field)
  ship(eng, ev, waitUntil);
  return new Response(null, {
    status: 302,
    headers: {
      location: to,
      'set-cookie': challengeCookie(await eng.kit.issue(ip, now), url.protocol === 'https:'),
      'cache-control': 'no-store',
    },
  });
}
