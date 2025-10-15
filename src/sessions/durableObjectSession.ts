import { SessionStrategy } from ".";
import type { SessionStrategyCfg, ProjectConfig } from "../core/types";
import { signJwtHS256, verifyJwtHS256 } from "../utils/jwt";
import { getCookie } from ".";
import type { Session } from ".";

// Opaque sid cookie + DO state; mints short-lived access JWT
export class DurableObjectSessionStrategy implements SessionStrategy {
	constructor(private cfg: SessionStrategyCfg & { kind: "durableObject" }) {}

	async resolve(request: Request, env: Env) {
		const sid = getCookie(request, this.cfg.cookieName ?? "__Host-sid");
		if (!sid) return { session: null };

		const stub = this.cfg.doName.getByName(sid);
		const res = await stub.fetch("https://do/session", {
			method: "POST",
			body: JSON.stringify({ op: "get" }),
		});
		if (!res.ok) return { session: null };

		const data = await res.json() as { session: Session | null };
		if (!data?.session) return { session: null };

		const now = Math.floor(Date.now() / 1000);
		const exp = now + 15 * 60;
		const accessJwt = await signJwtHS256(
			{
				sub: data.session.sub,
				email: data.session.email,
				iat: now,
				exp,
			},
			env[this.cfg.jwtSecretEnv as keyof Env]
		);
		return { session: data.session as Session, accessJwt };
	}

	async issue(session: Session, env: Env) {
		const sid = crypto.randomUUID();
		const stub = this.cfg.doName.getByName(sid);
		const ok = await stub.fetch("https://do/session", {
			method: "POST",
			body: JSON.stringify({ op: "put", session }),
		});
		if (!ok) throw new Error("session create failed");

		const now = Math.floor(Date.now() / 1000);
		const exp = now + 15 * 60;
		const accessJwt = await signJwtHS256(
			{
				sub: session.sub,
				email: session.email,
				iat: now,
				exp,
			},
			env[this.cfg.jwtSecretEnv]
		);
		return {
			cookie: `${this.cfg.cookieName ?? "__Host-sid"}=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax`,
			accessJwt,
		};
	}

	clear() {
		return {
			cookie: `${this.cfg.cookieName ?? "__Host-sid"}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
		};
	}
}