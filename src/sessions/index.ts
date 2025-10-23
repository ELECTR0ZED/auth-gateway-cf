import type { SessionStrategy, SessionStrategyCfg } from '../types';
import { JwtSessionStrategy } from './jwtSession';
import { DurableObjectSessionStrategy } from './durableObjectSession';

/**
 * Gets a cookie value from a request
 *
 * @export
 * @param {Request} req
 * @param {string} name
 * @returns {string | null}
 */
export function getCookie(req: Request, name: string): string | null {
	const h = req.headers.get('cookie');
	if (!h) return null;
	const m = h.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
	return m ? decodeURIComponent(m[1]) : null;
}

/**
 * Creates a session strategy based on configuration
 *
 * @export
 * @param {SessionStrategyCfg} sessionCfg
 * @returns {SessionStrategy}
 */
export function makeSessionStrategy(sessionCfg: SessionStrategyCfg): SessionStrategy {
	if (sessionCfg.kind === 'jwt') return new JwtSessionStrategy(sessionCfg);
	if (sessionCfg.kind === 'durableObject') return new DurableObjectSessionStrategy(sessionCfg);

	throw new Error(`unknown session strategy kind: ${(sessionCfg as SessionStrategyCfg).kind}`);
}
