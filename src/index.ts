import { Gateway } from './core/gateway';
import type { ProjectConfig } from './types';

export { SessionDO } from './do/sessionDo';

let gateway: Gateway | undefined;

export default function createGateway(cfg: ProjectConfig): ExportedHandler<Env> {
	return {
		async fetch(request, env, _ctx) {
			gateway ??= new Gateway(env, cfg);
			return gateway.fetch(request);
		},
	};
}

export function defineConfig(config: ProjectConfig): ProjectConfig {
	return config;
}

export type * from './types';
export * from './utils/verifyInternal';
