// src/utils/verifyInternal.ts
import type { ProjectConfig } from '../types';
import { decodeJsonFromBase64, signHmac, type PropagatedUserPayload } from './propagation';

export type VerifyGatewayUserOptions = {
	maxSkewSec?: number; // replay / clock-skew window
	require?: boolean; // throw instead of returning null
};

export async function verifyGatewayUser(
	request: Request,
	cfg: Pick<ProjectConfig, 'propagation'>,
	env: Env,
	options: VerifyGatewayUserOptions = {},
): Promise<PropagatedUserPayload | null> {
	const headerName = cfg.propagation.headerName ?? 'X-User';
	const sigHeaderName = cfg.propagation.sigHeaderName ?? 'X-User-Sig';

	const payloadB64 = request.headers.get(headerName);
	const sig = request.headers.get(sigHeaderName);

	if (!payloadB64 || !sig) {
		if (options.require) throw new Error('missing_user_headers');
		return null;
	}

	const secret = env[cfg.propagation.hmacSecretEnv];
	if (!secret) throw new Error('missing_hmac_secret');

	const computedSig = await signHmac(payloadB64, secret);
	if (!timingSafeEqual(computedSig, sig)) {
		if (options.require) throw new Error('bad_user_sig');
		return null;
	}

	let payload: unknown;
	try {
		payload = decodeJsonFromBase64(payloadB64);
	} catch {
		if (options.require) throw new Error('bad_user_payload');
		return null;
	}

	if (!isPropagatedUserPayload(payload)) {
		if (options.require) throw new Error('bad_user_shape');
		return null;
	}

	const maxSkewSec = options.maxSkewSec ?? 120;
	const now = Math.floor(Date.now() / 1000);
	if (Math.abs(now - payload.ts) > maxSkewSec) {
		if (options.require) throw new Error('user_ts_out_of_window');
		return null;
	}

	return payload;
}

function isPropagatedUserPayload(x: unknown): x is PropagatedUserPayload {
	if (!x || typeof x !== 'object') return false;
	const o = x as Record<string, unknown>;

	return (
		typeof o.userId === 'string' &&
		o.userId.length > 0 &&
		typeof o.email === 'string' &&
		o.email.length > 0 &&
		typeof o.ts === 'number' &&
		Number.isFinite(o.ts)
	);
}

/**
 * Timing-safe compare for short strings.
 * (Avoids early-return. Better than `===`.)
 */
function timingSafeEqual(a: string, b: string): boolean {
	let out = a.length ^ b.length;
	const len = Math.max(a.length, b.length);
	for (let i = 0; i < len; i++) {
		const ca = i < a.length ? a.charCodeAt(i) : 0;
		const cb = i < b.length ? b.charCodeAt(i) : 0;
		out |= ca ^ cb;
	}
	return out === 0;
}
