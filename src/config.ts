import { env } from "cloudflare:workers";
import type { ProjectConfig } from "./core/types";

export const CONFIG: ProjectConfig = {
	projectName: "demo-project",
	publicBaseUrl: "https://auth-microservice.electr0zed.workers.dev",
	providers: [
		{
			id: "discord",
			enabled: true,
			label: "Discord",
			clientId: "1425964712431980625",
			clientSecretEnv: "DISCORD_CLIENT_SECRET",
			scope: "identify email",
		}
	],
	defaultProvider: "discord",
	session: {
		kind: "durableObject",
		cookieName: "__Host-sid",
		doName: env.SESSION_DO,
		jwtSecretEnv: "SESSION_JWT_SECRET",
		idleTtlSec: 14 * 24 * 60 * 60,     // 14 days
  		absoluteTtlSec: 30 * 24 * 60 * 60, // 30 days
		issuer: "auth-gateway",
  		audience: "internal-services",
	},
	propagation: {
		headerName: "X-User",
		sigHeaderName: "X-User-Sig",
		hmacSecretEnv: "AUTH_HMAC_KEY",
	},
	routes: [
		{
			match: {
				path: /^\/admin(?:\/|$)/
			},
			auth: "required",
			service: env.HWWORKER,
		},
		{
			match: {
				path: /^.*/
			},
			auth: "none",
			service: env.HWWORKER,
		},
	]
};