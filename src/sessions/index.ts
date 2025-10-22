export function getCookie(req: Request, name: string) {
	const h = req.headers.get('cookie');
	if (!h) return null;
	const m = h.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
	return m ? decodeURIComponent(m[1]) : null;
}

export { JwtSessionStrategy } from './jwtSession';
export { DurableObjectSessionStrategy } from './durableObjectSession';
