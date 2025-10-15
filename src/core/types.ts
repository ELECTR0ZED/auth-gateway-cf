export {};

export type LoginProviderId = "azure_b2c" | "discord" | "github" | "google" | "entra";

export type Match = { path: string | RegExp; methods?: string[] };

export type RouteRule = {
	name?: string;
	match: Match | Match[];
	auth: "required" | "optional" | "none";
	service: Fetcher;
	rolesAny?: string[];
	rolesAll?: string[];
	scopesAny?: string[];
	allowIf?: string[]; // e.g., ["webhook:github"]
};

export type ProviderConfig = {
	id: LoginProviderId;
	enabled: boolean;
	label?: string;
	clientId: string;
	clientSecretEnv?: string; // env var name
	issuer?: string;
	authUrl?: string;
	tokenUrl?: string;
	userInfoUrl?: string;
	scope?: string; // "openid profile email"
	tenant?: string; // Azure B2C
	b2cPolicy?: string; // Azure B2C user flow
};

export type SessionStrategyCfg =
	| {
		kind: "jwt";
		cookieName?: string;
		expMinutes?: number;
		jwtSecretEnv: string;
	}
	| {
		kind: "durableObject";
		cookieName?: string;
		doName: DurableObjectNamespace;
		jwtSecretEnv: string;
	};

export type PropagationCfg = {
	headerName?: string;
	sigHeaderName?: string;
	hmacSecretEnv: string;
};

export type ProjectConfig = {
	projectName: string;
	publicBaseUrl: string;
	routes: RouteRule[];
	providers: ProviderConfig[];
	defaultProvider?: LoginProviderId;
	session: SessionStrategyCfg;
	propagation: PropagationCfg;
};

declare global {
	interface Env {
		[key: string]: string | undefined;
	}
}