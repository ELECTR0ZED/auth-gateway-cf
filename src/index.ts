import { Gateway } from './core/gateway';
import type { ProjectConfig } from './types';

export { SessionDO } from './do/sessionDo';

export default function createGateway(cfg: ProjectConfig): ExportedHandler<Env> {
	return {
		async fetch(request, env, _ctx) {
			const app = new Gateway(env, cfg);
			return app.fetch(request);
		},
	};
}

export function defineConfig(config: ProjectConfig): ProjectConfig {
	return config;
}

export type * from './types';
