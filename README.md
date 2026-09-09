# @camada/hono

camada for [Hono](https://hono.dev) on Cloudflare Workers: enforces the tenant snapshot inline
(your ordered custom rules, then block, allow, challenge), serves a first-party proof-of-work
challenge page and beacon, records the outcomes your handlers know (`track()`),
and ships wire events through `waitUntil` so nothing is on the response path.
Fails open by design — a camada outage or bug never 5xxes your app.

Not yet on npm — consumed via a `file:` dependency from a sibling checkout.

## Quickstart

```ts
import { Hono } from 'hono';
import { camada } from '@camada/hono';

const app = new Hono();
app.use('*', camada());        // reads CAMADA_KEY / CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL from the Worker env
app.get('/', (c) => c.text('hello'));
export default app;
```

Env (printed by camada onboarding / `npm run seed` in dev):

```
CAMADA_KEY=<ingest_token>.<snap_token>
CAMADA_INGEST_URL=http://localhost:8787        # dev only; defaults to production ingest
```

Workers hand env vars to the request, not to a process, so `camada()` builds its engine from
`c.env` on the first request. An app that reads its own config can pass the values instead:

```ts
app.use('*', camada({ key: MY_KEY, ingestUrl: MY_INGEST }));
```

## camada-backend (the dogfood mount — contracts §H, SEC-07)

Mount it in front of the API, and never in front of health or the Stripe webhook: those must
answer whatever the snapshot says.

```ts
import { camada } from '@camada/hono';

const guard = camada();                    // key, ingest and snapshot URLs come from c.env
const OPEN = new Set(['/api/health', '/api/stripe/webhook']);

app.use('/api/*', (c, next) => (OPEN.has(c.req.path) ? next() : guard(c, next)));
```

Call `camada()` once and reuse the handler. Engines are cached per resolved configuration, so
mounting the same config twice shares one snapshot poller and one event queue, while two mounts
with different keys or URLs each get their own — a Workers isolate hosting several Hono apps
never enforces one tenant's snapshot on another, nor signs its cookies with another's secret.

Without `CAMADA_KEY` the middleware is inert (one log line, no requests, no enforcement), so an
unprovisioned environment behaves exactly as if camada were not installed.

## What it does per request

1. Refreshes the snapshot off-path through `waitUntil` (lazy mode — no interval timers on an
   edge runtime). Every poll and event batch carries `x-camada-sdk: @camada/hono/<version>`,
   and polls ask for snapshot v5 (`x-camada-snapshot: 5`) — the container that carries your
   ordered custom rules.
2. Resolves the client from `cf-connecting-ip`, falling back to `X-Forwarded-For` under your
   tenant's trusted-proxy config. Neither header is ever trusted blindly: `cf-connecting-ip`
   counts only on Workers (where Cloudflare sets it and a client cannot forge it, and where
   `request.cf` proves it), and `X-Forwarded-For` counts only under a trusted-proxy config. On
   `@hono/node-server`, Bun or Deno the CF header is ignored — there it is just another header
   the caller controls.
3. Runs your ordered custom rules (see below), then the allow, block and challenge lists.
4. **Block** → `403` with `x-block-reason` before your handler; the event still ships, with
   `st: 403` and `blk: <reason>` so the analyst counts SDK blocks apart from your own 403s.
5. **Skip** → a skip rule or the allow list wins over a wider block (an allow-listed IP
   inside a blocked CIDR or ASN goes through).
6. **Challenge** → a `403` proof-of-work page (see below).
7. Otherwise your handler runs, and the settled response ships one batched, redacted event with
   its real status (Authorization and Cookie values never leave the isolate; credential-looking
   query values are scrubbed — see `@camada/core`).

## Custom rules

Your Rules page holds one ordered list per project, and this middleware walks it before the
allow, block and challenge lists. First match wins — the order *is* the precedence — and each
rule carries one of four actions:

| action | what the middleware does | on the event |
|---|---|---|
| `skip` | passes the request | nothing |
| `block` | `403` before your handler | `blk: "rule"`, `rl: "<rule id>"` |
| `challenge` | serves the proof-of-work page (`challenge: false` opts out) | `blk: "challenge"` |
| `warn` | passes the request and marks it for the analyst | `wrn: "<rule id>"` |

A skip rule also carries a *record matches* flag, which only the analyst reads: a recorded skip
is still scored and shows on your dashboard as Allowed, an unrecorded one is dropped before
scoring. Either way the request passes here, unstamped — the built-in Allow-list is a skip rule
with recording on.

A rule block also names the row that decided, so the response says which rule to edit:

```
HTTP/1.1 403 Forbidden
x-block-reason: rule
x-block-rule: cr_4f2a9c1b7e03
```

Every condition type enforces at this tap: `ip`, `path`, `ua` and `header` like everywhere else,
plus the `asn`, `country` and `tlsx` conditions only `request.cf` can judge. A `header`
condition (`is`, `contains`, `matches`) reads the name case-insensitively, and headers are the
request plane's alone — the analyst never sees them, so a header rule is enforced by a v5 SDK
like this one or not at all. A project that has not published the v5 container is answered with
v4 or v3, and the lists in it keep enforcing.

## The challenge (SDK-04)

A `challenge` verdict serves a self-contained 403 page: no external assets, `no-store`, and an
inline SHA-256 solver that finds a counter whose digest starts with 16 zero bits (tens of
milliseconds) and posts it to `POST /__camada/challenge`. That endpoint checks the nonce and the
work, sets `_cch` (an HMAC token, 1 h, `HttpOnly; SameSite=Lax`) and 302s back to the original
URL. Events: `{ st: 403, blk: "challenge" }` when served, `{ st: 200, ch: 1 }` when passed.

Requests that are not HTML navigations (no `text/html` in `Accept`, or a `sec-fetch-dest` other
than `document`) get `403 {"error":"challenge_required"}` instead — an API client should see a
status it can act on, not a page it cannot solve.

The nonce and the cookie are bound to the client IP, so a request camada cannot identify is
never challenged (it would mint a cookie any other unidentified client could present).

## Options

| option | default | meaning |
|---|---|---|
| `key` | `env.CAMADA_KEY` | `<ingest_token>.<snap_token>`; without it the middleware is inert |
| `ingestUrl` | `env.CAMADA_INGEST_URL` | ingest base; batches go to `<ingestUrl>/e` |
| `snapshotUrl` | `<ingestUrl>/snapshot` | snapshot endpoint |
| `trustedProxy` | server config | `none` / `vercel` / `hops:N` / `cidrs:a,b`, or the parsed object |
| `challenge` | `true` | serve the proof-of-work page for `challenge` verdicts |
| `challengePath` | `/__camada/challenge` | where that page posts its solution |
| `snapshotVersion` | `5` | `4` drops the custom rules, `3` the allow/challenge sides too |
| `scriptPath` | `/_cam/b.js` | where the first-party beacon script is served |
| `fpPath` | `/_cam/fp` | where that script posts the beacon; keep it in `scriptPath`'s directory |
| `env` | `c.env` | overrides the Worker env (tests) |

`CAMADA_CHALLENGE=0` in the Worker env switches the challenge off without a code change.

`CAMADA_DISABLED=1` in the Worker env switches everything off, checked per request.

## The first-party beacon

Bots that never run JavaScript are the cheapest to catch. Put the tag in the `<head>` of the
pages you render and the middleware does the rest:

```ts
import { camada, scriptTag } from '@camada/hono';

app.use('*', camada());
app.get('/', (c) => c.html(`<html><head>${scriptTag(c)}</head><body>…</body></html>`));
```

`scriptTag(c)` returns `<script src="/_cam/b.js?r=<rid>" async></script>` — the `rid` is this
request's event id, so the analyst joins the beacon to the page view. The middleware serves the
script at `GET /_cam/b.js` (cacheable, 1 h) and relays `POST /_cam/fp` (≤ 32 KB, answers 204)
onto the event batch as a `sig: 1` row stamped with the client ip camada resolved — never the
one the body claims. Both endpoints sit behind the verdict: a blocked client gets 403 there
too. The tag is `''` when camada is off for the request or the project turned the beacon off
in its settings, and the endpoints stand down with it.

Mounting on a prefix (`app.use('/api/*', camada())`) means `/_cam/*` never reaches the
middleware; move both paths under it — `camada({ scriptPath: '/api/_cam/b.js', fpPath:
'/api/_cam/fp' })` — the script derives the post path from its own `src`, so the two must
share a directory.

## App-context events

The wire shows a `POST /login`; only your handler knows whether it failed. Tell camada:

```ts
import { camada, track } from '@camada/hono';

app.post('/login', async (c) => {
  const ok = await signIn(c);
  if (!ok) track(c, 'login_failed', { user: email });   // await optional — the flush rides waitUntil
  return ok ? c.redirect('/') : c.text('Invalid credentials', 401);
});
```

`track(c, event, { user? })` ships `{ et, uid, rid, sid, ip, ts }` joined to this request's event.
The user identifier is HMAC-hashed in-process with the ingest token — the raw value never leaves
the isolate. It never throws and is a no-op where the middleware did not run. The event name is
free-form; the analyst's rules read this vocabulary:

| event | when |
|---|---|
| `login_failed` / `login_succeeded` | a credential check settled |
| `signup` | an account was created |
| `password_reset` | a reset was requested |
| `mfa_failed` | a second factor was rejected |
| `payment_failed` / `payment_succeeded` | a charge settled |
| `coupon_failed` | a promo code was rejected |

## What this tap can see

`request.cf` gives Workers the client's `asn`, `country`, `tlsClientExtensionsSha1` and
`httpProtocol`, so ASN, country and TLS-fingerprint rules genuinely enforce here — unlike a bare
Node app, which sees none of them. The connection terminates at Cloudflare, so the protocol on
the event is the visitor's own, not a proxy hop's (camada never reads a forwarded protocol
header for it). With the beacon and `track()` it is the full in-app position. workerd
normalises header order, so the raw-wire-order signal is the one thing not available here; the
analyst knows that from the tap's capability mask (`sdk-hono`) and never scores its absence as
evidence.

## Fail open

Every entry point runs inside camada's guard. A dead ingest, a corrupt snapshot, a bug in this
package: telemetry is lost, the request is not.
