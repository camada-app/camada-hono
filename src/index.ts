// @camada/hono — the one-line install for a Hono app on Cloudflare Workers:
//   app.use('*', camada());   // env: CAMADA_KEY (+ CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL in dev)
export { camada, resetCamada } from './camada.js';
export { resolveEnv, type CamadaHonoOptions, type ResolvedEnv } from './env.js';
