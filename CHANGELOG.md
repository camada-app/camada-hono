# Changelog

## Unreleased

Needs the `@camada/core` that exports `readBodyCapped`.

**Upgrade note.** Off Workers the client address is now the socket peer. Behind a proxy or load
balancer that address is the proxy's, on every request, where it used to be null under the
default trusted-proxy `none`. Set `CAMADA_TRUSTED_PROXY` (`hops:N` or `cidrs:…`) so the client is
read from `X-Forwarded-For`. Where `VERCEL` is set and nothing else is configured, the default is
now `vercel`.

### Fixed

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
