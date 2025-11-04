/* =========================================
 * Routing / Gateway
 * =======================================*/

export type Match = { path: string | RegExp; methods?: string[] };

export type RouteRule = {
	name?: string;
	match: Match | Match[];
	auth: 'required' | 'none';
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
	createdAt: number;
	updatedAt: number;
}

export type Session = {
	userId: string;
	email: string;
};

export interface SessionStrategy {
	resolve(request: Request, env: Env): Promise<{ session: Session | null; accessJwt?: string }>;
	issue?(session: Session, env: Env): Promise<{ cookie?: string; accessJwt?: string }>;
	clear?(): { cookie: string };
}

/* =========================================
 * Propagation / Project Config
 * =======================================*/

export type PropagationCfg = {
	headerName?: string;
	sigHeaderName?: string;
	hmacSecretEnv: string;
};

type StoreBackend = { kind: 'kv'; kv: KVNamespace } | { kind: 'postgres'; hyperdrive: Hyperdrive };

export type UserStoreCfg = StoreBackend & {
	shortStateKV: KVNamespace;
};

export type ProjectConfig = {
	projectName: string;
	publicBaseUrl: string;
	routes: RouteRule[];
	providers: ProviderConfig[];
	defaultProvider: LoginProviderId;
	session: SessionStrategyCfg;
	propagation: PropagationCfg;
	userStore: UserStoreCfg;
};

/* =========================================
 * User Store Contracts
 * =======================================*/

export interface UserCore {
	id: string;
	email: string;
}

export interface UserStore {
	findUserIdByIdentity(issuer: string, subject: string): Promise<string | null>;
	findUserIdByEmail(emailLower: string): Promise<string | null>;
	createUserWithIdentity(emailLower: string, identity: { provider: string; issuer: string; subject: string }): Promise<string>;
	addIdentityToUser(userId: string, identity: { provider: string; issuer: string; subject: string }): Promise<void>;
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
