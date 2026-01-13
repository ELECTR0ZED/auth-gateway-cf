// src/utils/turnstile.ts

export type TurnstileVerifyResult = { ok: true } | { ok: false; code: string; errors?: string[] };

type SiteverifyResponse = {
	success: boolean;
	'error-codes'?: string[];
	// Optional fields exist (challenge_ts, hostname, etc.) but not required here.
};

export async function verifyTurnstile(token: string, secret: string, remoteip?: string): Promise<TurnstileVerifyResult> {
	if (!token || typeof token !== 'string') {
		return { ok: false, code: 'turnstile_missing' };
	}

	const form = new FormData();
	form.append('secret', secret);
	form.append('response', token);
	if (remoteip) form.append('remoteip', remoteip);

	const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
		method: 'POST',
		body: form,
	});

	if (!res.ok) {
		return { ok: false, code: 'turnstile_unavailable' };
	}

	const data = (await res.json().catch(() => null)) as SiteverifyResponse | null;
	if (!data?.success) {
		return {
			ok: false,
			code: 'turnstile_invalid',
			errors: data?.['error-codes'] ?? [],
		};
	}

	return { ok: true };
}

export function getTurnstileTokenField(cfg?: { tokenField?: string }): string {
	return cfg?.tokenField ?? 'turnstileToken';
}
