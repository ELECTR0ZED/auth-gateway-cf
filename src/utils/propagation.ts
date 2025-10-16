// utils/propagation.ts
import type { ProjectConfig } from "../core/types";
import { Session } from "../sessions";

export async function attachSignedUser(
	headers: Headers,
	session: Session,
	cfg: ProjectConfig,
	env: Env
) {
	const name = cfg.propagation.headerName ?? "X-User";
	const sigName = cfg.propagation.sigHeaderName ?? "X-User-Sig";
	const secret = env[cfg.propagation.hmacSecretEnv];
	if (!secret) throw new Error("Missing HMAC secret");

	// Include a timestamp to prevent replay across services; receiver should enforce max age (e.g., 60s)
	const payloadObj = { session, ts: Math.floor(Date.now() / 1000) };
	const json = JSON.stringify(payloadObj);
	const payload = btoa(String.fromCharCode(...new Uint8Array(new TextEncoder().encode(json))));
	const sig = await signHmac(payload, secret as string);

	headers.set(name, payload);
	headers.set(sigName, sig);
}

export function stripUser(headers: Headers, cfg: ProjectConfig) {
	headers.delete(cfg.propagation.headerName ?? "X-User");
	headers.delete(cfg.propagation.sigHeaderName ?? "X-User-Sig");
}

async function signHmac(payload: string, secret: string): Promise<string> {
	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);
	const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
	const bytes = new Uint8Array(sigBuf);
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, ""); // base64url
}
