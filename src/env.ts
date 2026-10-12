// Workers hand env vars per request on `c.env`, not on a process — so the engine is built from
// whatever the first request carries, merged with the options the app passed in code.
import type { Context } from 'hono';
import { parseKey, parseTrustedProxyEnv, type SnapshotVersion, type TrustedProxyConfig } from '@camada/core';

export interface ResolvedEnv {
  ingestToken: string;
  snapToken: string;
  secret: string;                            // HMAC key for the challenge nonce/cookie — never leaves the isolate
  ingestUrl: string;
  snapshotUrl: string;
  trustedProxy: TrustedProxyConfig | null;   // null = defer to server-delivered config
}

export interface CamadaHonoOptions {
  key?: string;
  ingestUrl?: string;
  snapshotUrl?: string;
  trustedProxy?: TrustedProxyConfig | string | null;
  challenge?: boolean;            // enforce `challenge` verdicts with the first-party page (default true)
  challengePath?: string;         // where that page posts its solution (default /__camada/challenge)
  snapshotVersion?: SnapshotVersion;   // 5 (default) also carries the tenant's ordered custom rules; 4 the allow/challenge sides only; 3 opts out of both
  scriptPath?: string;            // where the first-party beacon script is served (default /_cam/b.js)
  fpPath?: string;                // where that script posts the beacon (default /_cam/fp; must share scriptPath's directory — the script derives it)
  env?: Record<string, string | undefined>;   // overrides c.env (tests, and apps that read config themselves)
  fetchImpl?: typeof fetch;
  /** Off Workers: the socket peer for this request, when the runtime object on `c.env` is not
   *  one camada reads itself (node-server, Bun, Deno) — e.g. `(c) => getConnInfo(c).remote.address`.
   *  Goes through the trusted-proxy rules with X-Forwarded-For. Never consulted on Workers. */
  peer?: (c: Context) => string | null | undefined;
  /** How rows reach ingest where there is no execution context (always per row through waitUntil
   *  where there is one). 'timer': batch on the queue's 15 s timer and drain on exit — for a
   *  long-lived server. 'lazy': flush every row as it is shipped — for a function that freezes after
   *  the response. Unset: 'timer' only on a recognised node-server / Bun / Deno server outside
   *  Vercel, AWS Lambda, Netlify and Deno Deploy, else 'lazy'. CAMADA_SERVERLESS=1 forces 'lazy'. */
  mode?: 'timer' | 'lazy';
}

/** A host variable: the merged env first (c.env + opts.env), then the process's own env
 *  (process.env, or Deno.env where the permission is already granted — never a prompt). A Deno
 *  without the permission API (Deno Deploy) has no prompt either, so its env is read directly:
 *  that is where DENO_DEPLOYMENT_ID tells a short-lived isolate apart from a long-lived server. */
export function hostVar(name: string, env: Record<string, string | undefined>): string | undefined {
  if (env[name] !== undefined) return env[name];
  const g = globalThis as {
    Deno?: { env?: { get?: (k: string) => string | undefined }; permissions?: { querySync?: (d: { name: string; variable: string }) => { state: string } } };
    process?: { env?: Record<string, string | undefined> };
  };
  try {
    if (g.Deno) {
      const query = g.Deno.permissions?.querySync;
      if (typeof query === 'function' && query.call(g.Deno.permissions, { name: 'env', variable: name }).state !== 'granted') return undefined;
      return g.Deno.env?.get?.(name);   // a throw (NotCapable) reads as unset, below
    }
    return g.process?.env?.[name];
  } catch { return undefined; }
}

const asProxy = (v: CamadaHonoOptions['trustedProxy']): TrustedProxyConfig | null =>
  typeof v === 'string' ? parseTrustedProxyEnv(v) : v ?? null;

/** Returns null (the middleware stays inert, one log line) rather than throwing on bad config. */
export function resolveEnv(opts: CamadaHonoOptions, env: Record<string, string | undefined>): ResolvedEnv | null {
  const raw = opts.key || env.CAMADA_KEY;
  const key = parseKey(raw);
  const ingestToken = key?.ingestToken ?? env.CAMADA_TOKEN;
  const snapToken = key?.snapToken ?? env.CAMADA_SNAPSHOT_TOKEN;
  if (!ingestToken || !snapToken) return null;
  const ingestUrl = (opts.ingestUrl || env.CAMADA_INGEST_URL || 'https://in.camada.app').replace(/\/$/, '');
  return {
    ingestToken, snapToken,
    secret: raw || `${ingestToken}.${snapToken}`,
    ingestUrl,
    snapshotUrl: opts.snapshotUrl || env.CAMADA_SNAPSHOT_URL || `${ingestUrl}/snapshot`,
    // On Vercel the platform rewrites X-Forwarded-For, so its rightmost entry is the client (as @camada/next).
    trustedProxy: asProxy(opts.trustedProxy) ?? parseTrustedProxyEnv(env.CAMADA_TRUSTED_PROXY)
      ?? (hostVar('VERCEL', env) ? { mode: 'vercel' } : null),
  };
}
