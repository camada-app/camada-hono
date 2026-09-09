// @camada/hono — the one-line install for a Hono app on Cloudflare Workers:
//   app.use('*', camada());   // env: CAMADA_KEY (+ CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL in dev)
//   c.html(`<head>${scriptTag(c)}</head>…`)   // the first-party beacon
//   track(c, 'login_failed', { user })         // an outcome the wire cannot show
export { camada, resetCamada } from './camada.js';
export { track, scriptTag } from './context.js';
export { resolveEnv, type CamadaHonoOptions, type ResolvedEnv } from './env.js';
