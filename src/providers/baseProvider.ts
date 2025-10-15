import type { ProviderConfig } from "../core/types";
import type { Session } from "../sessions";

/** Minimal OAuth token response shape we care about. */
type TokenResponse = {
	access_token?: string;
	id_token?: string;
	refresh_token?: string;
	token_type?: string;
	expires_in?: number;
	// Allow provider-specific extras without failing type-checking
	[key: string]: unknown;
};

/**
 * Base OIDC-ish provider with helpers for:
 * - authorize URL building (PKCE-ready)
 * - token exchange (authorization_code)
 * - id_token parsing and claim normalization
 *
 * Override minimal methods in concrete providers:
 * - getAuthorizeEndpoint()
 * - getTokenEndpoint()
 * - getDefaultScope()
 * - normalize() (if provider-specific claims differ)
 */
export abstract class AuthProvider {
	abstract id: string;

	// ---- Required per-provider endpoints ----
	protected abstract getAuthorizeEndpoint(cfg: ProviderConfig): string;
	protected abstract getTokenEndpoint(cfg: ProviderConfig): string;

	// ---- Optional overrides/hooks ----
	protected getDefaultScope(cfg: ProviderConfig): string {
		return cfg.scope ?? "openid profile email";
	}

	protected getRedirectUri(baseUrl: string): string {
		return `${baseUrl}/auth/callback`;
	}

	protected getClientSecret(env: Env, cfg: ProviderConfig): string | undefined {
		const key = cfg.clientSecretEnv;
		return key ? env[key] : undefined;
	}

	/**
	 * Build the authorization URL (adds PKCE params, scope, and state/returnTo).
	 * You can override to add provider-specific params.
	 */
	loginURL(
		cfg: ProviderConfig,
		baseUrl: string,
		state: string,
		codeChallenge: string,
		returnTo?: string
	): string {
		const authorize = this.getAuthorizeEndpoint(cfg);
		const scope = this.getDefaultScope(cfg);
		const redirectUri = this.getRedirectUri(baseUrl);
		const stateParam = returnTo ? state + "::" + returnTo : state;

		const qp = new URLSearchParams({
			client_id: cfg.clientId,
			response_type: "code",
			redirect_uri: redirectUri,
			scope,
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
			state: stateParam,
		});

		return `${authorize}?${qp.toString()}`;
	}

	/**
	 * Exchange auth code for tokens. Override if a provider needs special params.
	 */
	async exchangeCode(
		cfg: ProviderConfig,
		env: Env,
		code: string,
		codeVerifier: string,
		redirectUri: string
	): Promise<{ session: Session; idToken?: string; accessToken?: string; refreshToken?: string }> {
		const tokenUrl = this.getTokenEndpoint(cfg);
		const scope = this.getDefaultScope(cfg);
		const clientSecret = this.getClientSecret(env, cfg);

		const body = new URLSearchParams({
			client_id: cfg.clientId,
			code,
			code_verifier: codeVerifier,
			grant_type: "authorization_code",
			redirect_uri: redirectUri,
			scope,
		});
		if (clientSecret) body.set("client_secret", clientSecret);

		const res = await fetch(tokenUrl, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body,
		});
		if (!res.ok) {
			const text = await res.text().catch(() => "");
			throw new Error(`token exchange failed: ${res.status} ${text}`);
		}

		const json = (await res.json()) as TokenResponse;

		// Prefer id_token for claims; fall back to userinfo if absent
		let claims: any;
		if (typeof json.id_token === "string") {
			claims = this.parseJwt(json.id_token);
		} else if (typeof json.access_token === "string") {
			const info = await this.fetchUserInfo(cfg, json.access_token);
			claims = info.claims;
		} else {
			claims = {};
		}

		return {
			session: this.normalize(claims),
			idToken: typeof json.id_token === "string" ? json.id_token : undefined,
			accessToken: typeof json.access_token === "string" ? json.access_token : undefined,
			refreshToken: typeof json.refresh_token === "string" ? json.refresh_token : undefined,
		};
	}

	/**
	 * Optional userinfo call if provider doesn’t send id_token (most do).
	 */
	protected async fetchUserInfo(cfg: ProviderConfig, accessToken: string): Promise<{ claims: any }> {
		if (!cfg.userInfoUrl) return { claims: {} };
		const r = await fetch(cfg.userInfoUrl, { headers: { authorization: `Bearer ${accessToken}` } });
		if (!r.ok) throw new Error(`userinfo failed: ${r.status}`);
		const claims = (await r.json()) as any;
		return { claims };
	}

	protected normalize(claims: any): Session {
		const email = claims?.email || claims?.emails?.[0];
		const roles = (claims?.roles as string[] | undefined) ?? (claims?.groups as string[] | undefined) ?? [];
		return { sub: claims.sub, email, roles, claims };
	}

	protected parseJwt(token: string): any {
		const [, p] = token.split(".");
		return JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/")));
	}
}
