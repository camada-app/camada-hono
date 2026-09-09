// Per-request state the middleware leaves on the Hono context for the two helpers an app calls
// from its own handlers: `scriptTag(c)` (the beacon tag) and `track(c, event, data)` (an
// app-context outcome). The key is private — the helpers are the API, not `c.get`. When the
// middleware did not run for this request (a path it is not mounted on, no key, CAMADA_DISABLED,
// or a request it answered itself) there is nothing on the context and both helpers stand down.
import type { Context } from 'hono';
import { guarded, guardedAsync, hashUserId, logRateLimited, TAP_HONO } from '@camada/core';
import type { Engine, WaitUntil } from './camada.js';

export const VAR = '__camada';

export interface CamadaVars {
  eng: Engine;
  rid: string;            // the request id the page event carries; the beacon and track() join on it
  sid: string;            // the `_sfp` session — the one just minted when the request arrived without it
  ip: string | null;
  waitUntil: WaitUntil;
  scriptPath: string;
}

export const beaconEnabled = (e: Engine): boolean => e.snap.config?.beacon !== false;   // tenant switch; a cold engine serves

const readVars = (c: Context): CamadaVars | undefined => c.get(VAR) as CamadaVars | undefined;

/**
 * Records an outcome the app knows and the wire cannot show: `login_failed`, `login_succeeded`,
 * `signup`, `password_reset`, `mfa_failed`, `payment_failed`, `payment_succeeded`, `coupon_failed`
 * (free-form; that vocabulary is what the analyst's rules read). Joined to this request's event
 * through its rid and session. The user identifier is HMAC-hashed in-process with the ingest
 * token — the raw value never reaches the queue. Never throws, never rejects; awaiting it is
 * optional (the flush rides `waitUntil`), so a handler may fire and forget.
 */
export function track(c: Context, event: string, data?: { user?: string }): Promise<void> {
  return guardedAsync(async () => {
    const vars = readVars(c);
    if (!vars) return;
    const { eng, rid, sid, ip, waitUntil } = vars;
    const p = (async () => {
      const uid = data?.user ? await hashUserId(data.user, eng.env.ingestToken, crypto.subtle) : null;
      eng.queue.push({ tap: TAP_HONO, et: event, uid, rid, sid, ip, ts: Date.now() });
      eng.queue.flush(waitUntil);   // the isolate may freeze right after the response: flush now, held open by waitUntil
    })().catch(logRateLimited);
    waitUntil(p);
    await p;
  }, undefined);
}

/** The `<script>` tag for an HTML response — `''` when camada is off for this request or the tenant turned the beacon off. */
export function scriptTag(c: Context): string {
  return guarded(() => {
    const vars = readVars(c);
    if (!vars || !beaconEnabled(vars.eng)) return '';
    return `<script src="${vars.scriptPath}?r=${vars.rid}" async></script>`;
  }, '');
}
