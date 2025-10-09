import { Gateway } from './core/gateway';
import type { Env } from './core/types';

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const app = new Gateway(env);
		return app.fetch(request);
	},
} satisfies ExportedHandler<Env>;
