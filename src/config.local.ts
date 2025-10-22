import { env } from 'cloudflare:workers';
import type { ProjectConfig } from './types';

export const CONFIG: ProjectConfig = {
	projectName: 'demo-project',
	publicBaseUrl: 'http://127.0.0.1:8787',
	providers: [
		{
			id: 'google',
			enabled: true,
			label: 'Google',
			clientId: '783906859341-qsramgvo2iogotttgc3v2pk3hv6cehs9.apps.googleusercontent.com',
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
		kind: 'kv',
		kv: env.USER_STORE_KV,
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
};
