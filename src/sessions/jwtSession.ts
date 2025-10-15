import { SessionStrategy } from ".";
import type { SessionStrategyCfg, ProjectConfig } from "../core/types";
import { signJwtHS256, verifyJwtHS256 } from "../utils/jwt";
import { getCookie } from ".";
import type { Session } from ".";

// Stateless cookie that IS the JWT
export class JwtSessionStrategy implements SessionStrategy {
	constructor(private cfg: SessionStrategyCfg & { kind: "jwt" }) {}

	async resolve(request: Request, env: Env) {
		const token = getCookie(request, this.cfg.cookieName ?? "__Host-session");
		if (!token) return { session: null };

		try {
			const payload = await verifyJwtHS256(token, env[this.cfg.jwtSecretEnv]);
			return {
				session: {
					sub: payload.sub,
					email: payload.email,
					roles: payload.roles,
					claims: payload,
				},
			};
		} catch {
			return { session: null };
		}
	}

	async issue(session: Session, env: Env) {
		const expMinutes = this.cfg.expMinutes ?? 15;
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signJwtHS256(
			{
				sub: session.sub,
				email: session.email,
				roles: session.roles,
				iat: now,
				exp: now + expMinutes * 60,
			},
			env[this.cfg.jwtSecretEnv]
		);
		return {
			cookie: `${this.cfg.cookieName ?? "__Host-session"}=${jwt}; Path=/; HttpOnly; Secure; SameSite=Lax`,
		};
	}

	clear() {
		return {
			cookie: `${this.cfg.cookieName ?? "__Host-session"}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
		};
	}
}