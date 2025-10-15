import { Gateway } from './core/gateway';

export { SessionDO } from './do/sessionDo';

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const app = new Gateway(env);
		return app.fetch(request);
	},
} satisfies ExportedHandler<Env>;