import { Gateway } from './core/gateway';

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const app = new Gateway(env);
		return app.fetch(request);
	},
} satisfies ExportedHandler<Env>;
