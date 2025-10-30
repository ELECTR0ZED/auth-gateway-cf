import { Gateway } from './core/gateway';
import { CONFIG } from './config';

export { SessionDO } from './do/sessionDo';

export default {
	async fetch(request, env): Promise<Response> {
		const app = new Gateway(env, CONFIG);
		return app.fetch(request);
	},
} satisfies ExportedHandler<Env>;
