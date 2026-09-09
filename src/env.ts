// Workers hand env vars per request on `c.env`, not on a process — so the engine is built from
// whatever the first request carries, merged with the options the app passed in code.
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
  const ingestUrl = (opts.ingestUrl || env.CAMADA_INGEST_URL || 'https://in.camada.dev').replace(/\/$/, '');   // PLACEHOLDER default — confirm the production ingest domain before any npm publish
  return {
    ingestToken, snapToken,
    secret: raw || `${ingestToken}.${snapToken}`,
    ingestUrl,
    snapshotUrl: opts.snapshotUrl || env.CAMADA_SNAPSHOT_URL || `${ingestUrl}/snapshot`,
    trustedProxy: asProxy(opts.trustedProxy) ?? parseTrustedProxyEnv(env.CAMADA_TRUSTED_PROXY),
  };
}
