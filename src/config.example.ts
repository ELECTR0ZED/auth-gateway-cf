import { env } from 'cloudflare:workers';
import { defineConfig } from '.';

defineConfig({
	projectName: 'demo-project',
	publicBaseUrl: 'http://domain.com',
	providers: [
		{
			id: 'google',
			enabled: true,
			label: 'Google',
			clientId: 'clientId',
			clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
		},
	],
	defaultProvider: 'google',
	session: {
		kind: 'durableObject',
		cookieName: '__Host-sid',
		doName: env.SESSION_DO,
		jwtSecretEnv: 'SESSION_JWT_SECRET',
		idleTtlSec: 14 * 24 * 60 * 60, // 14 days
		absoluteTtlSec: 30 * 24 * 60 * 60, // 30 days
		issuer: 'auth-gateway',
		audience: 'internal-services',
	},
	userStore: {
		kind: 'postgres',
		hyperdrive: env.USERSTORE,
	},
	propagation: {
		headerName: 'X-User',
		sigHeaderName: 'X-User-Sig',
		hmacSecretEnv: 'AUTH_HMAC_KEY',
	},
	routes: [
		{
			match: {
				path: /^\/admin(?:\/|$)/,
			},
			auth: 'required',
			service: env.HWWORKER,
		},
		{
			match: {
				path: /^.*/,
			},
			auth: 'none',
			service: env.HWWORKER,
		},
	],
});
