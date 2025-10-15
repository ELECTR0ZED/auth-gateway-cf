import type { ProjectConfig } from "./core/types";

export const CONFIG: ProjectConfig = {
	projectName: "my-single-project",
	publicBaseUrl: "http://127.0.0.1:8787",
	providers: [
		{
			id: "discord",
			enabled: true,
			label: "Discord",
			clientId: "1425964712431980625",
			clientSecretEnv: "DISCORD_CLIENT_SECRET",
			scope: "identify email"
		}
	],
	defaultProvider: "discord",
	session: { kind: "handle", cookieName: "__Host-sid", doName: "SESSION_DO" },
	propagation: { headerName: "X-User", sigHeaderName: "X-User-Sig", hmacSecretEnv: "AUTH_HMAC_KEY" },
	routes: [
		{ match: [{ path: "/api**" }, { path: "/dashboard/**" }], auth: "required" },
		{ match: { path: "/admin**" }, auth: "required" },
		{ match: { path: "**" }, auth: "none" },
	],
	policies: {
		beforeAuth: [],
		afterAuth: []
	}
};