// src/utils/http.ts

export function json(obj: unknown, init: ResponseInit = {}): Response {
	return new Response(JSON.stringify(obj), {
		...init,
		headers: {
			...(init.headers ? Object.fromEntries(new Headers(init.headers)) : {}),
			'content-type': 'application/json',
		},
	});
}

export async function readJson<T = unknown>(request: Request): Promise<{ ok: true; body: T } | { ok: false; code: string }> {
	const ct = request.headers.get('content-type') || '';
	if (!ct.includes('application/json')) return { ok: false, code: 'bad_content_type' };

	try {
		const body = (await request.json()) as T;
		return { ok: true, body };
	} catch {
		return { ok: false, code: 'bad_json' };
	}
}
