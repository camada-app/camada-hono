// The SDK's wire identity (SDK-03): x-camada-sdk: <package>/<version>. Named JSON imports are
// inlined and tree-shaken by tsup at build, so dist carries two literals — no runtime fs read.
import { name, version } from '../package.json';
export const SDK_ID = `${name}/${version}`;
