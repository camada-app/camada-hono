# Changelog

## Unreleased

### Fixed

- A signalled response (`x-camada-challenge: 1`) now also sets `cdn-cache-control`,
  `surrogate-control`, `cloudflare-cdn-cache-control`, `vercel-cdn-cache-control` and
  `netlify-cdn-cache-control` to `no-store`, overriding the app's. CDNs read those ahead of
  `cache-control`, so an app-set one could still let a shared cache keep the per-client copy.
  (camada-all-5pog)

## 0.3.4 (2026-10-12; follows 0.3.3)

Needs the `@camada/core` that exports `readBodyCapped`.

**Upgrade note.** Off Workers the client address is now the socket peer. Behind a proxy or load
balancer that address is the proxy's, on every request, where it used to be null under the
default trusted-proxy `none`. Set `CAMADA_TRUSTED_PROXY` (`hops:N` or `cidrs:…`) so the client is
read from `X-Forwarded-For`. Where `VERCEL` is set and nothing else is configured, the default is
now `vercel`.

### Fixed

- A camada answer that sets its own cookie (the 302 after a passed challenge, with `_cch`) no
  longer deletes every Set-Cookie an upstream middleware added: only a cookie of the same name is
  replaced, so the app's session cookie survives. (camada-all-mwpo)
- Block responses (path, ip, asn, country, tls and rule blocks, the `Forbidden` 403) now send `cache-control: no-store`, like the challenge answers, so a shared cache cannot serve one visitor's block to others. An upstream `cache-control` on `c.res` is replaced. (camada-all-8lp6)
- Every answer camada gives itself (challenge page, re-issued page, JSON 403, beacon script) keeps
  its own headers when a middleware in front of camada set some through `c.res.headers` (or
  `c.header()` after anything read `c.res`). Hono merged those over the answer, so an upstream
  `cache-control: public, max-age=600` could land on the IP-bound challenge 403 (a shared cache
  would serve it to others), and an upstream `Set-Cookie` replaced the passed challenge's `_cch`
  cookie. A report-only policy is still dropped. (camada-all-mwpo)
- A Deno whose permission API has no `querySync` (before 1.37) no longer reads `Deno.env.get`
  directly, which could stop the server on a permission prompt. (camada-all-wc27)
- On Deno Deploy (no `Deno.permissions`), `DENO_DEPLOYMENT_ID` is read through `Deno.env.get`
  instead of being treated as unset, so events flush per row there instead of waiting for a 15 s
  timer in a short-lived isolate. With the permission API present, a variable not already granted
  is still never read. (camada-all-wc27)
- Off Workers with per-row flushing and no execution context (`hono/vercel`), each flush is handed
  to Vercel's request-context `waitUntil` when one is present, as `@camada/next` does. (camada-all-wc27)
- The challenge page (served and re-issued after a wrong answer) sends its own
  `Content-Security-Policy` (core's `challengePageCsp()`: only its inline solver and style, by
  hash), and a policy a middleware in front of camada set on `c.res` or with `c.header()` no
  longer rides along on it, where a strict policy blocked the solver. Register `camada()` before
  `secureHeaders({ contentSecurityPolicy })`, which sets its policy after the response.
  (camada-all-mwpo)
- A chunked (length-less) POST to `/_cam/fp` or the challenge path is cut off at the 32 KB / 4 KB
  cap and its stream cancelled, instead of being read whole before the cap was checked (an
  unauthenticated memory DoS). The client sees `413`, or a connection reset on `@hono/node-server`,
  which stops reading the upload. The challenge cap now counts bytes, not UTF-16 units
  (camada-all-4u4i).
- On `@hono/node-server`, Bun and Deno the client address is the socket peer (from the runtime
  object on `c.env`), under the trusted-proxy rules. It was always null there under the default
  `none`: no IP rule matched and no challenge was served (camada-all-kri7).
- On a long-lived `@hono/node-server`, Bun or Deno server, events no longer POST `/e` once per
  request: they batch on the queue timer and drain on process exit. Serverless hosts without an
  execution context (`hono/vercel`, `netlify`, `aws-lambda`, `lambda-edge`, or `VERCEL`,
  `AWS_LAMBDA_FUNCTION_NAME`, `NETLIFY`, `DENO_DEPLOYMENT_ID` set, or `CAMADA_SERVERLESS=1`) still
  flush every row as it is shipped and get no exit handlers. On Workers every row still flushes
  through `waitUntil` (camada-all-wc27).
- The runtime's socket peer is read only on its own runtime and never where an execution context
  exists, so a Workers binding named `server` or `incoming` is never called as a server.
- `trustedProxy` defaults to `vercel` where `VERCEL` is set and nothing else is configured.

### Added

- `peer` option: `(c) => string | null`, the socket peer on a host camada does not read itself
  (camada-all-kri7).
- `mode` option: `'timer'` (batch, drain on exit) or `'lazy'` (flush per row) off Workers; detected
  when unset (camada-all-wc27).

### Changed

- The `exports` map now gives `require` its own `.d.cts` declarations (`import` and `require` each carry a `types` condition), so a CommonJS TypeScript app on `moduleResolution: node16` compiles; CI runs `@arethetypeswrong/cli`. (camada-all-vuzm)

## 0.3.3 (2026-10-09; follows 0.3.2)

Needs `@camada/core` 0.5.1.

### Fixed

- The snapshot client no longer re-polls back to back when `/snapshot` fails. It keeps its blocks and
  waits max(`retry-after`, 5 s), capped at the refresh interval (through `@camada/core` 0.5.1,
  camada-all-pbv9).

## 0.3.2 (2026-10-04; follows 0.3.1)

Needs `@camada/core` 0.5.0.

### Added

- `x-rid` response header: the rid of the request's event row, on every response the app answers
  (a faithful copy when the headers are immutable). Not on camada's own answers or a 101.

### Changed

- `ts` is the request start, so `[ts, ts + dur]` is when the request ran.
- `dur` for a `text/event-stream` response runs to its last byte, or until the client leaves
  (`waitUntil` holds a Workers isolate until then). Any other response ships at once, with
  `dur` = time to first byte.
- The app's Response object still goes out as is. Only an SSE body is re-wrapped, with the same
  status and headers.

### Fixed

- Path rules match the canonical path (through `@camada/core` 0.5.0). A percent-encoded,
  upper-cased or trailing-slash spelling of a blocked path used to slip past the block.
- WebSocket upgrades ship one event with `st: 101` on every runtime: workerd, Deno, Bun
  (`hono/bun`) and Node (`@hono/node-ws`). On Deno 2.9 an upgrade used to ship no event, because
  the request is closed once `Deno.upgradeWebSocket` returns. On Bun, only a request that
  `server.upgrade()` took is recorded as 101. A plain `GET` carrying `Upgrade: websocket` that your
  handler answered records the status it sent.
- A first visit gets the `_sfp` session cookie on immutable responses (a `fetch()` result,
  `Response.redirect()`), through a faithful copy, and on `HEAD` under `@hono/node-server` 1.x.
  The copy keeps the status, headers and body bytes. A WebSocket 101 is never copied and gets no
  cookie.
