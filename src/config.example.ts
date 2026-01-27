import { defineConfig } from '.';

defineConfig({
	projectName: 'demo-project',
	publicBaseUrl: 'http://domain.com',
	oAuth: {
		enabled: true,
		defaultProvider: 'google',
		providers: [
			{
				id: 'google',
				enabled: true,
				label: 'Google',
				clientId: 'clientId',
				clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
			},
		],
	},
	passwordAuth: {
		enabled: true,
		pepperEnv: 'PASSWORD_PEPPERS',
		allowSignup: true,
		turnstile: {
			enabled: true,
			secretEnv: 'TURNSTILE_SECRET',
			tokenField: 'turnstileToken',
		},
	},
	session: {
		kind: 'durableObject',
		cookieName: '__Host-sid',
		doName: {} as DurableObjectNamespace<import('./index').SessionDO>,
		jwtSecretEnv: 'SESSION_JWT_SECRET',
		idleTtlSec: 14 * 24 * 60 * 60, // 14 days
		absoluteTtlSec: 30 * 24 * 60 * 60, // 30 days
		issuer: 'auth-gateway',
		audience: 'internal-services',
	},
	userStore: {
		kind: 'postgres',
		hyperdrive: {} as Hyperdrive,
		shortStateKV: {} as KVNamespace,
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
			service: {} as Service,
		},
		{
			match: {
				path: /^.*/,
			},
			auth: 'none',
			service: {} as Service,
		},
	],
	overrides: {
		globalUnauthenticatedRedirectUrl: '/custom-login',
		accountApproval: {
			enabled: true,
		},
		emailVerification: {
			enabled: true,
			requiredForLogin: true,
		},
		autoLoginAfterSignup: true,
	},
});
