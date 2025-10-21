export type Session = {
	sub: string;
	email?: string;
	claims?: Record<string, any>;
};

export interface SessionStrategy {
	resolve(
		request: Request,
		env: Env
	): Promise<{ session: Session | null; accessJwt?: string }>;
	issue?(
		session: Session,
		env: Env
	): Promise<{ cookie?: string; accessJwt?: string }>;
	clear?(env: Env): { cookie: string };
}

export function getCookie(req: Request, name: string) {
	const h = req.headers.get("cookie");
	if (!h) return null;
	const m = h.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
	return m ? decodeURIComponent(m[1]) : null;
}

export { JwtSessionStrategy } from "./jwtSession";
export { DurableObjectSessionStrategy } from "./durableObjectSession";