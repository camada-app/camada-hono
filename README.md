# @camada/hono

camada for [Hono](https://hono.dev) on Cloudflare Workers: enforces the tenant snapshot inline
(block, allow, challenge), serves a first-party proof-of-work challenge page, and ships wire
events through `waitUntil` so nothing is on the response path. Fails open by design — a camada
outage or bug never 5xxes your app.

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
   and polls ask for snapshot v4 (`x-camada-snapshot: 4`).
2. Resolves the client from `cf-connecting-ip`, falling back to `X-Forwarded-For` under your
   tenant's trusted-proxy config. Neither header is ever trusted blindly: `cf-connecting-ip`
   counts only on Workers (where Cloudflare sets it and a client cannot forge it, and where
   `request.cf` proves it), and `X-Forwarded-For` counts only under a trusted-proxy config. On
   `@hono/node-server`, Bun or Deno the CF header is ignored — there it is just another header
   the caller controls.
3. **Block** → `403` with `x-block-reason` before your handler; the event still ships, with
   `st: 403` and `blk: <reason>` so the analyst counts SDK blocks apart from your own 403s.
4. **Allow** → the v4 allow list wins over a wider block (an allow-listed IP inside a blocked
   CIDR or ASN goes through).
5. **Challenge** → a `403` proof-of-work page (see below).
6. Otherwise your handler runs, and the settled response ships one batched, redacted event with
   its real status (Authorization and Cookie values never leave the isolate; credential-looking
   query values are scrubbed — see `@camada/core`).

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
| `snapshotVersion` | `4` | `3` opts out of the v4 allow/challenge sections |
| `env` | `c.env` | overrides the Worker env (tests) |

`CAMADA_CHALLENGE=0` in the Worker env switches the challenge off without a code change.

`CAMADA_DISABLED=1` in the Worker env switches everything off, checked per request.

## What this tap can see

`request.cf` gives Workers the client's `asn`, `country`, `tlsClientExtensionsSha1` and
`httpProtocol`, so ASN, country and TLS-fingerprint rules genuinely enforce here — unlike a bare
Node app, which sees none of them. The connection terminates at Cloudflare, so the protocol on
the event is the visitor's own, not a proxy hop's (camada never reads a forwarded protocol
header for it). workerd normalises header order, so the raw-wire-order signal is not available
at this position; the analyst knows that from the tap's capability mask (`sdk-hono`) and never
scores its absence as evidence.

## Fail open

Every entry point runs inside camada's guard. A dead ingest, a corrupt snapshot, a bug in this
package: telemetry is lost, the request is not.
