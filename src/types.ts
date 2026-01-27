/* =========================================
 * Routing / Gateway
 * =======================================*/

import type { DB } from './stores/postgres';

export type Match = { path: string | RegExp; methods?: string[] };

export type RouteRule = {
	name?: string;
	match: Match | Match[];
	auth: 'required' | 'none';
	requireRolesAny?: string[];
	requireRolesAll?: string[];
	bypassAuthForStaticAssets?: boolean;
	unauthenticatedRedirectUrl?: string;
	service: Fetcher;
};

/* =========================================
 * Provider IDs & Config
 * =======================================*/

export type LoginProviderId = 'google';

export type ProviderConfig = {
	id: LoginProviderId;
	enabled: boolean;
	label?: string;
	clientId: string;
	clientSecretEnv?: string;
	issuer?: string;
	authUrl?: string;
	tokenUrl?: string;
	userInfoUrl?: string;
	scope?: string;
	tenant?: string;
	b2cPolicy?: string;
};

/* =========================================
 * Claims / Provider Runtime Contracts
 * =======================================*/

/** What each provider must extract from its claims. */
export type NormalizedClaims = {
	email: string; // required (your policy)
	subject: string; // provider's stable subject (claims.sub usually)
};

export type ClaimsMode = 'id_token' | 'userinfo';

/** Static wiring for a provider (URLs & defaults). */
export type ProviderStatic = {
	id: LoginProviderId;
	authorizeEndpoint: string;
	tokenEndpoint: string;
	defaultIssuer: string;
	defaultScope?: string; // e.g. "openid email profile"
	userInfoEndpoint?: string; // if you want a userinfo fallback
	claimsMode: ClaimsMode; // default claims extraction mode
};

/** Provider-normalized identity output (minimal) */
export type ProviderIdentity = {
	email: string;
	provider: LoginProviderId;
	issuer: string;
	subject: string;
};

/* =========================================
 * System Roles
 * =======================================*/

export type SystemRole = string;

/* =========================================
 * Session Strategy / Session Shapes
 * =======================================*/

export type SessionStrategyCfg =
	| {
			kind: 'jwt';
			cookieName?: string;
			expMinutes?: number;
			jwtSecretEnv: string;
	  }
	| {
			kind: 'durableObject';
			cookieName?: string;
			doName: DurableObjectNamespace<import('./index').SessionDO>;
			jwtSecretEnv: string;
			idleTtlSec?: number;
			absoluteTtlSec?: number;
			issuer?: string;
			audience?: string;
	  };

/** Minimal persistent session payload */
export interface StoredSession {
	userId: string;
	email: string;
	systemRoles: SystemRole[];
	createdAt: number;
	updatedAt: number;
}

export type Session = {
	userId: string;
	email: string;
	systemRoles: SystemRole[];
};

export interface SessionStrategy {
	resolve(request: Request, env: Env): Promise<{ session: Session | null; accessJwt?: string }>;
	issue?(session: Session, env: Env): Promise<{ cookie?: string; accessJwt?: string }>;
	clear?(): { cookie: string };
}

/* =========================================
 * Auth Config
 * =======================================*/

export type OAuthCfg =
	| {
			enabled: true;
			providers: ProviderConfig[];
			defaultProvider: LoginProviderId;
	  }
	| { enabled: false };

export type PasswordPolicy = {
	minLength: number;
	requireUppercase?: boolean;
	requireLowercase?: boolean;
	requireNumber?: boolean;
	requireSymbol?: boolean;
};

export type TurnstileCfg =
	| {
			enabled: true;

			/**
			 * Env var that contains the Turnstile secret key.
			 * (Configurable like your other secrets)
			 */
			secretEnv: string;

			/**
			 * JSON field name that carries the token.
			 * Default: "turnstileToken"
			 */
			tokenField?: string;
	  }
	| { enabled: false };

export type PasswordAuthCfg =
	| {
			enabled: true;

			/**
			 * Env var that contains comma-separated peppers (newest first).
			 * Example value: "pepper_v2,pepper_v1"
			 *
			 * Defaults to "PASSWORD_PEPPERS" if omitted.
			 */
			pepperEnv: string;

			policy?: PasswordPolicy;
			allowSignup: boolean;

			turnstile?: TurnstileCfg;
	  }
	| { enabled: false };

/* =========================================
 * Overrides
 * =======================================*/

export type ConfigOverrides = {
	staticAssetRegex?: RegExp;
	globalUnauthenticatedRedirectUrl?: string;

	accountApproval: {
		enabled: boolean;
	};
	emailVerification:
		| {
				enabled: true;
				requiredForLogin: boolean;
		  }
		| { enabled: false; requiredForLogin?: false };

	autoLoginAfterSignup: boolean;
	captureUsername:
		| {
				enabled: true;
				missingUsernameMethod: 'generate' | 'reject' | 'ignore';
				minLength?: number;
		  }
		| { enabled: false };
};

/* =========================================
 * Propagation / Project Config
 * =======================================*/

export type PropagationCfg = {
	headerName?: string;
	sigHeaderName?: string;
	hmacSecretEnv: string;
};

type StoreBackend = { kind: 'postgres'; hyperdrive: Hyperdrive };

export type UserStoreCfg = StoreBackend & {
	shortStateKV: KVNamespace;
};

export type ProjectConfig = {
	projectName: string;
	publicBaseUrl: string;
	routes: RouteRule[];
	session: SessionStrategyCfg;
	propagation: PropagationCfg;
	userStore: UserStoreCfg;
	oAuth: OAuthCfg;
	passwordAuth: PasswordAuthCfg;
	overrides?: ConfigOverrides;
};

/* =========================================
 * User Store Contracts
 * =======================================*/

export interface UserCore {
	id: string;
	email: string;
	systemRoles: SystemRole[];
}

export interface UserStore {
	findUserIdByIdentity(issuer: string, subject: string): Promise<string | null>;
	findUserIdByEmail(emailLower: string): Promise<string | null>;
	createUserWithIdentity(emailLower: string, identity: { provider: string; issuer: string; subject: string }): Promise<string>;
	addIdentityToUser(userId: string, identity: { provider: string; issuer: string; subject: string }): Promise<void>;
	getUserRoles(userId: string): Promise<SystemRole[]>;
	getUserStates(userId: string): Promise<DB['user_states'] | null>;

	createUserWithPassword(emailLower: string, passwordHash: string): Promise<string>;
	getPasswordHashByUserId(userId: string): Promise<string | null>;
	getUserIdByEmailForPassword(emailLower: string): Promise<{ userId: string; passwordHash: string } | null>;
	setPasswordHash(userId: string, passwordHash: string): Promise<void>;
}

/* =========================================
 * Auth Short-State (PKCE) Types
 * =======================================*/

export type StateMode = 'login' | 'link';

export type StateInfo = {
	mode: StateMode;
	returnTo?: string;
	provider?: string;
};

export type StoredPkce = {
	v: string; // verifier
	i: StateInfo; // info
};

/* =========================================
 * OAuth Token Response Shape
 * =======================================*/

export type TokenResponse = {
	access_token?: string;
	id_token?: string;
	refresh_token?: string;
	token_type?: string;
	expires_in?: number;
	[key: string]: unknown;
};

/* =========================================
 * Global Env Declaration
 * =======================================*/

declare global {
	interface Env {
		[key: string]: string | undefined;
	}
}
