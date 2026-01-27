import { SessionStrategy, Session, SessionStrategyCfg } from '../types';
import { signJwtHS256 } from '../utils/jwt';
import { getCookie } from '.';

export class DurableObjectSessionStrategy implements SessionStrategy {
	constructor(
		private cfg: (SessionStrategyCfg & { kind: 'durableObject' }) & {
			issuer?: string;
			audience?: string;
		},
	) {}

	async resolve(request: Request, env: Env) {
		const sid = getCookie(request, this.cfg.cookieName ?? '__Host-sid');
		if (!sid) return { session: null };

		const stub = this.cfg.doName.getByName(sid);
		const res = await stub.fetch('https://do/session', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ op: 'get' }),
		});
		if (!res.ok) return { session: null };

		const data = (await res.json().catch(() => null)) as { session?: Session | null } | null;
		if (!data?.session) return { session: null };

		const now = Math.floor(Date.now() / 1000);
		const exp = now + 15 * 60;
		const accessJwt = await signJwtHS256(
			{
				iss: this.cfg.issuer ?? 'auth-gateway',
				aud: this.cfg.audience ?? 'internal-services',
				sub: data.session.userId,
				email: data.session.email,
				iat: now,
				nbf: now - 30,
				exp,
				jti: crypto.randomUUID(),
			},
			env[this.cfg.jwtSecretEnv]!,
		);

		return { session: data.session as Session, accessJwt };
	}

	async issue(session: Session, env: Env) {
		const sid = crypto.randomUUID();
		const stub = this.cfg.doName.getByName(sid);

		const idleTtlSec = this.cfg.idleTtlSec ?? 14 * 24 * 60 * 60;
		const absoluteTtlSec = this.cfg.absoluteTtlSec ?? 30 * 24 * 60 * 60;

		const res = await stub.fetch('https://do/session', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ op: 'put', session, idleTtlSec, absoluteTtlSec }),
		});
		if (!res.ok) throw new Error('session create failed');

		const now = Math.floor(Date.now() / 1000);
		const exp = now + 15 * 60;
		const accessJwt = await signJwtHS256(
			{
				iss: this.cfg.issuer ?? 'auth-gateway',
				aud: this.cfg.audience ?? 'internal-services',
				sub: session.userId,
				email: session.email,
				iat: now,
				nbf: now - 30,
				exp,
				jti: crypto.randomUUID(),
			},
			env[this.cfg.jwtSecretEnv]!,
		);

		const cookieName = this.cfg.cookieName ?? '__Host-sid';
		return {
			cookie: `${cookieName}=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${idleTtlSec}; Priority=Medium`,
			accessJwt,
		};
	}

	clear() {
		return {
			cookie: `${this.cfg.cookieName ?? '__Host-sid'}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
		};
	}
}
