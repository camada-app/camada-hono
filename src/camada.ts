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
  guarded, createChallengeAsync, challengePage, challengePageCsp, challengeCookie, safeReturnTo, wantsHtml, parseFormBody, readBodyCapped,
  CHALLENGE_COOKIE, DEFAULT_SNAPSHOT_VERSION, TAP_HONO,
  type AsyncChallengeKit, type TrustedProxyConfig, type WireEvent,
} from '@camada/core';
import { withSetCookie, withRid } from '@camada/core/fetch';
import { resolveEnv, hostVar, type CamadaHonoOptions, type ResolvedEnv } from './env.js';
import { VAR, beaconEnabled, type CamadaVars } from './context.js';
import { SDK_ID } from './version.js';

const DEFAULT_CHALLENGE_PATH = '/__camada/challenge';
const SCRIPT_PATH = '/_cam/b.js';   // the beacon IIFE; its auto-init posts to the sibling `fp` and reads the rid from ?r=
const FP_PATH = '/_cam/fp';
const FP_MAX = 32 * 1024;        // matches the analyst's /fp cap: never accept what ingest will 413
const SESSION_COOKIE = '_sfp';   // the same session cookie as every other tap: sid/ns stay comparable
const SESSION_MAX_AGE = 2592000;
const BODY_MAX = 4 * 1024;       // the verify form is ~120 bytes; anything larger is not ours

export interface Engine {
  env: ResolvedEnv;
  snap: SnapshotClient;
  queue: EventQueue;
  kit: AsyncChallengeKit;
}

export type WaitUntil = (p: Promise<unknown>) => void;
/** Off Workers in a long-lived process: nothing to hold open, and the queue timer batches the rows. */
const noWait: WaitUntil = () => {};
/** Off Workers in a function that freezes after the response: nothing to hold open either, but
 *  every row flushes as it is shipped — a row left for the timer would never go out. */
const flushNow: WaitUntil = () => {};

/** The host's request-scoped waitUntil where Vercel provides one (`@vercel/functions` reads the same
 *  global; @camada/next's wait-until.ts too): hono/vercel passes no execution context, so without it
 *  the function may freeze before a flush started at the response is done. Null elsewhere. */
function requestContextWaitUntil(): WaitUntil | null {
  return guarded(() => {
    const g = globalThis as Record<symbol, { get?: () => { waitUntil?: WaitUntil } | undefined } | undefined>;
    const ctx = g[Symbol.for('@vercel/request-context')]?.get?.();
    if (typeof ctx?.waitUntil !== 'function') return null;
    return (p: Promise<unknown>) => { try { ctx.waitUntil!(p); } catch { /* a context that refuses costs only the hold */ } };
  }, null);
}

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

interface BunServer { requestIP: (req: Request) => unknown }

interface CfProps { asn?: number; country?: string; tlsClientExtensionsSha1?: string; httpProtocol?: string }
const cfOf = (req: Request): CfProps => ((req as Request & { cf?: CfProps }).cf ?? {});

const trustedProxy = (e: Engine): TrustedProxyConfig | null =>
  e.env.trustedProxy ?? e.snap.config?.trusted_proxy ?? null;

const runtime = globalThis as { Bun?: unknown; Deno?: unknown; navigator?: { userAgent?: string }; process?: { versions?: { node?: string } } };
const onWorkers = (): boolean => runtime.navigator?.userAgent === 'Cloudflare-Workers';

/** The long-lived server Hono runs under, recognised from the object it hands the app as `c.env`
 *  (no static import of hono/bun etc., so a Workers bundle pulls none of them), and a reader for
 *  the socket peer it vouches for. Each shape is read only on its own runtime, so a Workers
 *  binding that happens to be named `server` or `incoming` (a JS-RPC stub answers any property
 *  with a callable) is never called:
 *  @hono/node-server `{ incoming }` → `incoming.socket.remoteAddress` (Node or Bun, not Workers);
 *  Bun `Bun.serve({ fetch: app.fetch })` → the server (or hono/bun's `{ server }`) →
 *  `requestIP(req).address`; Deno `Deno.serve(app.fetch)` → `info.remoteAddr.hostname`.
 *  Null for anything else: Workers bindings, hono/vercel, netlify, aws-lambda, lambda-edge. */
function serverShape(env: unknown): ((req: Request) => string | null) | null {
  if (!env || typeof env !== 'object' || onWorkers()) return null;
  const e = env as { incoming?: { socket?: { remoteAddress?: unknown } }; server?: unknown; remoteAddr?: { hostname?: unknown } };
  const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null);
  if (runtime.process?.versions?.node && e.incoming && typeof e.incoming === 'object') return () => str(e.incoming?.socket?.remoteAddress);
  if (runtime.Bun !== undefined) {
    const bun = ('server' in e ? e.server : e) as BunServer | undefined;   // hono/bun's getBunServer
    if (typeof bun?.requestIP === 'function') return (req) => str((bun.requestIP(req) as { address?: unknown } | null)?.address);
  }
  if (runtime.Deno !== undefined && e.remoteAddr && typeof e.remoteAddr === 'object') return () => str(e.remoteAddr?.hostname);
  return null;
}

/** Serverless hosts whose functions freeze after the response, whatever object they hand `c.env`. */
const SERVERLESS_HOSTS = ['VERCEL', 'AWS_LAMBDA_FUNCTION_NAME', 'NETLIFY', 'DENO_DEPLOYMENT_ID'];

/** Whether rows wait for the queue timer (a process that outlives the response) rather than
 *  each flushing as it is shipped. Only where there is no execution context to hold open. */
function batches(opts: CamadaHonoOptions, env: Record<string, string | undefined>, runtimeEnv: unknown): boolean {
  if (hostVar('CAMADA_SERVERLESS', env) === '1') return false;
  if (opts.mode) return opts.mode === 'timer';
  if (SERVERLESS_HOSTS.some((k) => hostVar(k, env))) return false;
  return serverShape(runtimeEnv) !== null;
}

/** Cloudflare sets `cf-connecting-ip` itself and a client cannot forge it — but only on
 *  Workers, which is also the only place `request.cf` exists. On any other Hono runtime
 *  (node-server, Bun, Deno) that header is attacker-controlled, so it is ignored there: the
 *  socket peer (the app's `peer(c)`, else the runtime's own) and X-Forwarded-For go through the
 *  trusted-proxy rules instead, as on every other adapter. */
const clientIp = (e: Engine, req: Request, peer: string | null): string | null => {
  const cf = (req as Request & { cf?: unknown }).cf;
  if (cf) return req.headers.get('cf-connecting-ip') || resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(e));
  return resolveClientIp(peer, req.headers.get('x-forwarded-for'), trustedProxy(e));
};

/** The peer for a request off Workers; never consulted where `request.cf` or an execution
 *  context exists (a Workers env holds bindings, not a server). Never throws. */
const peerOf = (opts: CamadaHonoOptions, c: Context, hasCtx: boolean): string | null => guarded(() => {
  if (hasCtx || (c.req.raw as Request & { cf?: unknown }).cf) return null;
  if (opts.peer) return opts.peer(c) || null;
  return serverShape(c.env)?.(c.req.raw) ?? null;
}, null);

interface RequestFacts {
  url: URL;
  path: string;
  cf: CfProps;
  ip: string | null;
  sid: string | null;
}

function describeRequest(e: Engine, req: Request, peer: string | null): RequestFacts {
  const url = new URL(req.url);
  const cookies = req.headers.get('cookie') || '';
  return { url, path: url.pathname, cf: cfOf(req), ip: clientIp(e, req, peer), sid: cookieValue(cookies, SESSION_COOKIE) };
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

/** Push, then flush through `waitUntil` (Workers, or Vercel's request context) or at once (`flushNow`, serverless without an
 *  execution context): the function may freeze right after the response, so each row goes out
 *  with it. In a long-lived process (`noWait`) the queue's timer batches the rows — one POST /e per
 *  flush, not one per request (core's 7u3r rule). The one rule every row (wire event, beacon,
 *  track()) follows. */
export function ship(e: Engine, ev: unknown, waitUntil: WaitUntil): void {
  e.queue.push(ev);
  if (waitUntil !== noWait) e.queue.flush(waitUntil);
}

/** 204 and a `sig: 1` row on the event batch — one request per flush at the analyst, not one per page view. */
async function relayBeacon(eng: Engine, req: Request, ip: string | null, waitUntil: WaitUntil): Promise<Response> {
  const noContent = () => new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
  const body = await readBodyCapped(req, FP_MAX);   // streamed: a chunked body cannot buffer past the cap
  if (body === null) return new Response(null, { status: 413 });
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
    const t0 = Date.now();   // request start; the response event ships ts = t0 and dur = settle - t0 (ms), @camada/node's semantics
    // Reading c.env and building the engine are inside the guard too: a Workers env carries
    // non-string bindings, and a throw here would 5xx the app on its very first request.
    const env = guarded(() => ({ ...(c.env as Record<string, string | undefined> | undefined), ...opts.env }), {} as Record<string, string | undefined>);
    const eng = guarded(() => (env.CAMADA_DISABLED === '1' ? null : ensure(opts, env)), null);
    if (!eng) return next();
    // Same opt-out as @camada/next: the code option, or CAMADA_CHALLENGE=0 in the Worker env.
    const challengeOn = opts.challenge !== false && env.CAMADA_CHALLENGE !== '0';

    // Hono's executionCtx getter throws where the runtime passed none (node-server, Bun, Deno).
    let ctx: Context['executionCtx'] | null = null;
    try { ctx = typeof c.executionCtx?.waitUntil === 'function' ? c.executionCtx : null; } catch { /* expected off Workers: not an error to log */ }
    const batch = !ctx && guarded(() => batches(opts, env, c.env), false);
    const waitUntil: WaitUntil = ctx
      ? (p) => { try { ctx.waitUntil(p); } catch { /* a context that refuses: the row ships with the next flush */ } }
      : batch ? noWait : requestContextWaitUntil() ?? flushNow;
    // A batching process waits on the queue timer, so drain what is queued on exit (core's timer mode does the same).
    if (batch) guarded(() => eng.queue.installNodeExitFlush(), undefined);
    const peer = peerOf(opts, c, ctx !== null);

    // The id of the `warn` rule that let this request through, read again after next() when the
    // response event is built (§D3). Every other action settles before the app ever runs.
    let warnRule: string | null = null;
    // Set on the capture path only: the ids this request shares with the app (scriptTag, track)
    // and with its own post-response event. Null when camada answered the request itself.
    let vars: CamadaVars | null = null;
    let newSession = false;
    // A non-HTML request that passed under a challenge: x-camada-challenge: 1 and chs: 1 (82ar).
    let signalled = false;

    const answer = await guardedAsync(async (): Promise<Response | null> => {
      eng.snap.ensureFresh(waitUntil);

      const req = c.req.raw;
      const { url, path, cf, ip, sid } = describeRequest(eng, req, peer);

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
          'content-type': 'text/plain', 'cache-control': 'no-store', 'x-block-reason': String(v.reason ?? ''), 'x-block-version': v.version ?? '',
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
          // Only a page can be challenged; any other request passes to the app, signalled.
          if (wantsHtml(req.headers.get('accept'), req.headers.get('sec-fetch-dest'))) return serve(eng, req, ip, sid, challengePath, path + url.search, waitUntil);
          signalled = true;
        }
      }

      // The beacon endpoints come after enforcement (a blocked client, or one served the challenge
      // page, gets neither the script nor a relay; a challenged non-HTML client is only signalled
      // and still reaches them) and before the app (they are camada's, not its) — @camada/node's order.
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

    if (answer) {
      // Hono merges the headers of a c.res an app middleware in front of camada touched (c.res.headers,
      // or c.header() once anything read c.res) over the response returned here: an upstream
      // `cache-control: public` would make the IP-bound challenge cacheable, its CSP would block the
      // solver, its Set-Cookie of the same name would replace the `_cch` one. So set c.res to the answer, then put every
      // header of the answer back on top and drop a report-only policy (camada-all-mwpo, R7-1).
      return guarded(() => {
        c.res = answer;
        const h = c.res.headers;
        if (h === answer.headers) return answer;   // nothing was merged in
        for (const [k, v] of answer.headers) if (k !== 'set-cookie') h.set(k, v);
        const cookies = answer.headers.getSetCookie();
        if (cookies.length > 0) {
          // The answer's cookie wins only on a name clash; the app's own (a session, say) are kept (RF-2).
          const name = (ck: string) => ck.slice(0, Math.max(ck.indexOf('='), 0)).trim();
          const ours = new Set(cookies.map(name));
          const kept = h.getSetCookie().filter((ck) => !ours.has(name(ck)));
          h.delete('set-cookie');
          for (const ck of [...kept, ...cookies]) h.append('set-cookie', ck);
        }
        h.delete('content-security-policy-report-only');
        return c.res;
      }, answer);
    }

    // Read the request now, before the app runs: after Deno.upgradeWebSocket it is closed and
    // reading its headers throws. `vars` is null only when the guard above threw before setting
    // it — then the event still ships, with fresh ids.
    const req = c.req.raw;
    const method = req.method;
    const wsRequest = guarded(() => req.headers.get('upgrade')?.toLowerCase() === 'websocket', false);
    // On Bun (hono/bun), c.env is the server, and server.upgrade() detaches the request from its
    // socket: server.requestIP() turns null. That is the upgrade test there, since Bun keeps a string or
    // Blob body's implicit Content-Type outside res.headers and a bare 200 alone is not proof.
    const bun = wsRequest ? guarded(() => {
      const e = c.env as { server?: unknown } | undefined;
      const s = (e && 'server' in e ? e.server : e) as BunServer | undefined;   // hono/bun's getBunServer
      return typeof s?.requestIP === 'function' && s.requestIP(req) ? s : null;
    }, null) : null;
    const ev = guarded(() => {
      const { url, path, ip } = describeRequest(eng, req, peer);
      return buildEvent(req, path, url.search, ip, vars?.sid ?? null, vars?.rid, newSession);
    }, null);

    await next();

    // The handler has answered, so this tap ships the real status — unlike @camada/next's
    // middleware position, which can only report pre-response. A server-sent-events body ships
    // once it has gone out (or the client left), so dur covers the stream, and waitUntil holds
    // the isolate until then (on workerd through a native pipe that sees the client leave). Any
    // other response ships now and is left exactly as the app returned it (see onBodyDone).
    // Bun (hono/bun) and @hono/node-ws answer an accepted WebSocket upgrade with a bare
    // `new Response()` (200, no Content-Type) that the server discards as it switches protocols;
    // Deno and workerd hand back the 101 itself.
    const upgraded = wsRequest && c.res.status === 200 && !c.res.headers.has('content-type')
      && (bun ? guarded(() => bun.requestIP(req) === null, false) : true);
    const status = upgraded ? 101 : c.res.status;
    const shipEvent = () => void guardedAsync(async () => {
      if (!ev) return;
      const cfg = eng.snap.config;
      // a signalled row ships whatever sample and exclude say, like the 403 row it replaces
      if (signalled) ev.chs = 1;
      else if ((cfg?.exclude || []).some((x) => (ev.p as string).startsWith(x)) || Math.random() >= (cfg?.sample ?? 1)) return;
      ev.ts = t0;   // the request start: the timeline draws [ts, ts + dur]
      ev.st = status;
      ev.dur = Math.max(0, Date.now() - t0);
      if (warnRule) ev.wrn = warnRule;   // §D3: the warn rule that let this request through
      ship(eng, ev, waitUntil);
    }, undefined);
    try {
      // onBodyDone hands back c.res itself unless it wrapped an SSE body: any copy loses a 101
      // upgrade on Deno < 2.6, Bun's implicit Content-Type and, on Bun < 1.2.10, an empty body's
      // status and headers.
      replaceRes(c, onBodyDone(c.res, shipEvent, { method, waitUntil, get signal() { return c.req.raw.signal; } }));   // signal read on workerd only
    } catch (err) {
      logRateLimited(err);   // a locked or foreign body: ship now (time to first byte), the response untouched
      shipEvent();
    }

    // Stamp x-rid (the rid of the shipped row) and mint the shared session cookie the other taps
    // use, so `sid`/`ns` are real here too (ea's capability mask for sdk-hono claims SESSION).
    // Never overwrite an existing cookie. After the wrap, on the response that goes out:
    // @hono/node-server 1.x rebuilds a wrapped (or HEAD) response from its original init, so a
    // header set before would be lost. An immutable response (a fetch() result, Response.redirect())
    // gets core's faithful copy; a 101 never does (core's withRid skips it too), since Deno < 2.6
    // stops Deno.serve over a copied upgrade.
    // Hono answers HEAD with `new Response(null, <the GET response>)`, rebuilt the same way. So a
    // HEAD gets that copy built here, exactly as Hono would build it, with the headers in its init.
    // Where the copy throws (node-server 1.x on an init-less response), the app's 500 goes out as is.
    guarded(() => {
      if (c.res.status === 101) return;
      const rid = ev?.rid as string | undefined;
      let cookie: string | undefined;
      if (vars && newSession) {
        const secure = new URL(c.req.raw.url).protocol === 'https:' ? '; Secure' : '';
        cookie = `${SESSION_COOKIE}=${vars.sid}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; SameSite=Lax${secure}`;
      }
      if (!rid && !cookie) return;   // signalled implies a captured request, so rid is set
      if (method !== 'HEAD') {
        let out = c.res;
        if (cookie) out = withSetCookie(out, cookie);
        if (rid) out = withRid(out, { rid, signalled });
        return replaceRes(c, out);
      }
      const head = new Response(null, c.res);
      const headers = new Headers(head.headers);
      if (cookie) headers.append('set-cookie', cookie);
      if (rid) headers.set('x-rid', rid);
      if (signalled) headers.set('x-camada-challenge', '1');
      replaceRes(c, new Response(null, { status: head.status, statusText: head.statusText, headers }));
    }, undefined);
  };
}

/** Sends `out` in place of c.res when it is a different object. Hono's c.res setter would copy it
 *  again and copy the old response's headers back over it: the stale Content-Encoding/Length
 *  copyResponse dropped from a Deno-decoded fetch() body, and a set-cookie list without ours.
 *  `out` is already a faithful copy of c.res, so it goes in as is: the setter only merges into a
 *  response it already holds. */
function replaceRes(c: Context, out: Response): void {
  if (out === c.res) return;
  c.res = undefined;
  c.res = out;
}

/** 403 + the proof-of-work page (HTML navigations), plus the `blk: "challenge"` event. */
async function serve(eng: Engine, req: Request, ip: string, sid: string | null, action: string, target: string, waitUntil: WaitUntil): Promise<Response> {
  const url = new URL(req.url);
  const ev = buildEvent(req, url.pathname, url.search, ip, sid);
  ev.st = 403;
  ev.blk = 'challenge';
  ship(eng, ev, waitUntil);

  const html = challengePage({ nonce: await eng.kit.nonce(ip, Date.now()), action, to: safeReturnTo(target) });
  return new Response(html, {
    status: 403,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1', 'content-security-policy': challengePageCsp() },
  });
}

/** POST from the page: validate, set `_cch`, 302 back, ship `{ st: 200, ch: 1 }`. */
async function verify(eng: Engine, req: Request, ip: string, sid: string | null, action: string, waitUntil: WaitUntil): Promise<Response> {
  const url = new URL(req.url);
  // camada answers this path before the app runs, so it must not become a place to post
  // hundreds of megabytes at an unauthenticated endpoint.
  const body = await readBodyCapped(req, BODY_MAX);
  if (body === null) return new Response(null, { status: 413 });
  const form = parseFormBody(body);
  const to = safeReturnTo(form.to);
  const now = Date.now();
  if (!(await eng.kit.verify(ip, now, form.nonce, form.solution))) {
    const html = challengePage({ nonce: await eng.kit.nonce(ip, now), action, to });
    return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': challengePageCsp() } });
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
