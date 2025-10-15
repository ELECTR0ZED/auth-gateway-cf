export type LoginProviderId = "azure_b2c" | "discord" | "github" | "google" | "entra";

export type Match = { path: string | RegExp; methods?: string[] };

export type RouteRule = {
  name?: string;
  match: Match | Match[];
  auth: "required" | "optional" | "none";
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
  | { kind: "jwt"; cookieName?: string; expMinutes?: number; jwtSecretEnv: string }
  | { kind: "handle"; cookieName?: string; doName: "SESSION_DO" };

export type PropagationCfg = {
  headerName?: string;      // default: X-User
  sigHeaderName?: string;   // default: X-User-Sig
  hmacSecretEnv: string;    // e.g. AUTH_HMAC_KEY
};

export type ProjectConfig = {
  projectName: string;
  publicBaseUrl: string;        // https://example.com
  routes: RouteRule[];
  providers: ProviderConfig[];
  defaultProvider?: LoginProviderId;
  session: SessionStrategyCfg;  // choose "jwt" or "handle"
  propagation: PropagationCfg;
  policies?: { beforeAuth?: string[]; afterAuth?: string[] };
};

export type Env = {
  FE: Service;
  API: Service;
  AUTH_KV: KVNamespace;
  SESSION_DO: DurableObjectNamespace;
  // secrets
  AUTH_JWT_SECRET?: string;
  ACCESS_JWT_SECRET?: string;
  AUTH_HMAC_KEY?: string;
  // provider secrets by name
  [key: string]: any;
};