import { SessionStrategy, Session, SessionStrategyCfg } from '../types';
import { signJwtHS256, verifyJwtHS256 } from '../utils/jwt';
import { getCookie } from '.';

// Stateless cookie that IS the JWT
export class JwtSessionStrategy implements SessionStrategy {
	constructor(private cfg: SessionStrategyCfg & { kind: 'jwt' }) {}

	async resolve(request: Request, env: Env) {
		const token = getCookie(request, this.cfg.cookieName ?? '__Host-session');
		if (!token) return { session: null };

		try {
			const payload = await verifyJwtHS256(token, env[this.cfg.jwtSecretEnv]!);
			return {
				session: {
					userId: payload.sub,
					email: payload.email,
				} as Session,
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
				sub: session.userId,
				email: session.email,
				iat: now,
				nbf: now - 30,
				exp: now + expMinutes * 60,
				jti: crypto.randomUUID(),
			},
			env[this.cfg.jwtSecretEnv]!,
		);
		return {
			cookie: `${this.cfg.cookieName ?? '__Host-session'}=${jwt}; Path=/; HttpOnly; Secure; SameSite=Lax`,
		};
	}

	async clear(_request: Request, _env: Env) {
		return {
			cookie: `${this.cfg.cookieName ?? '__Host-session'}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
		};
	}
}
