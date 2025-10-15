import type { ProjectConfig } from "../core/types";

export type Session = {
	sub: string;
	email?: string;
	claims?: Record<string, any>;
};

export interface SessionStrategy {
	resolve(
		request: Request,
		env: Env,
		cfg: ProjectConfig
	): Promise<{ session: Session | null; accessJwt?: string }>;
	issue?(
		session: Session,
		env: Env,
		cfg: ProjectConfig
	): Promise<{ cookie?: string; accessJwt?: string }>;
	clear?(env: Env, cfg: ProjectConfig): { cookie: string };
}

export function getCookie(req: Request, name: string) {
	const h = req.headers.get("cookie");
	if (!h) return null;
	const m = h.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
	return m ? decodeURIComponent(m[1]) : null;
}

export { JwtSessionStrategy } from "./jwtSession";
export { DurableObjectSessionStrategy } from "./durableObjectSession";