export type Match = { path: string | RegExp; methods?: string[] };

export type RouteRule = {
	name?: string;
	match: Match | Match[];
	auth: 'required' | 'none';
	service: Fetcher;
};

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
			doName: DurableObjectNamespace<import('../index').SessionDO>;
			jwtSecretEnv: string;
			idleTtlSec?: number;
			absoluteTtlSec?: number;
			issuer?: string;
			audience?: string;
	  };

export type PropagationCfg = {
	headerName?: string;
	sigHeaderName?: string;
	hmacSecretEnv: string;
};

export type UserStoreCfg = { kind: 'kv'; kv: KVNamespace } | { kind: 'postgres'; connectionString: string };

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

/** Minimal persistent session payload */
export interface StoredSession {
	userId: string;
	email: string;
	createdAt: number;
	updatedAt: number;
}

/** Provider-normalized identity output (minimal) */
export type ProviderIdentity = {
	email: string;
	provider: LoginProviderId;
	issuer: string;
	subject: string;
};

/** User store contracts */
export interface UserCore {
	id: string;
	email: string;
}

declare global {
	interface Env {
		[key: string]: string | undefined;
	}
}

export interface UserStore {
	findUserIdByIdentity(issuer: string, subject: string): Promise<string | null>;
	findUserIdByEmail(emailLower: string): Promise<string | null>;
	createUserWithIdentity(emailLower: string, identity: { provider: string; issuer: string; subject: string }): Promise<string>;
	addIdentityToUser(userId: string, identity: { provider: string; issuer: string; subject: string }): Promise<void>;
}

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

export type Session = {
	userId: string;
	email: string;
};

export interface SessionStrategy {
	resolve(request: Request, env: Env): Promise<{ session: Session | null; accessJwt?: string }>;
	issue?(session: Session, env: Env): Promise<{ cookie?: string; accessJwt?: string }>;
	clear?(): { cookie: string };
}

export type TokenResponse = {
	access_token?: string;
	id_token?: string;
	refresh_token?: string;
	token_type?: string;
	expires_in?: number;
	[key: string]: unknown;
};
