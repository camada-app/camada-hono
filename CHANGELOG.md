# Changelog

## 0.3.2 (unreleased; follows 0.3.1)

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
