import type {
	ProviderConfig,
	LoginProviderId,
	ProviderIdentity,
	TokenResponse,
	ProviderStatic,
	NormalizedClaims,
	ClaimsMode,
} from '../types';

export abstract class AuthProvider {
	readonly id: LoginProviderId;
	private readonly authorizeEndpoint: string;
	private readonly tokenEndpoint: string;
	private readonly defaultIssuer: string;
	private readonly defaultScope?: string;
	private readonly userInfoEndpoint?: string;
	private readonly claimsMode: ClaimsMode;

	constructor(staticCfg: ProviderStatic) {
		this.id = staticCfg.id;
		this.authorizeEndpoint = staticCfg.authorizeEndpoint;
		this.tokenEndpoint = staticCfg.tokenEndpoint;
		this.defaultIssuer = staticCfg.defaultIssuer;
		this.defaultScope = staticCfg.defaultScope;
		this.userInfoEndpoint = staticCfg.userInfoEndpoint;
		this.claimsMode = staticCfg.claimsMode;
	}

	protected abstract normalize(claims: unknown): NormalizedClaims;

	protected getDefaultScope(cfg: ProviderConfig): string {
		return cfg.scope ?? this.defaultScope ?? 'openid email profile';
	}

	protected getRedirectUri(baseUrl: string): string {
		return `${baseUrl}/auth/callback`;
	}

	protected getClientSecret(env: Env, cfg: ProviderConfig): string | undefined {
		const key = cfg.clientSecretEnv;
		return key ? env[key] : undefined;
	}

	loginURL(cfg: ProviderConfig, baseUrl: string, state: string, codeChallenge: string): string {
		const scope = this.getDefaultScope(cfg);
		const redirectUri = this.getRedirectUri(baseUrl);

		const qp = new URLSearchParams({
			client_id: cfg.clientId,
			response_type: 'code',
			redirect_uri: redirectUri,
			scope,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
			state,
		});

		return `${this.authorizeEndpoint}?${qp.toString()}`;
	}

	async exchangeCode(cfg: ProviderConfig, env: Env, code: string, codeVerifier: string, redirectUri: string): Promise<ProviderIdentity> {
		const scope = this.getDefaultScope(cfg);
		const clientSecret = this.getClientSecret(env, cfg);

		const body = new URLSearchParams({
			client_id: cfg.clientId,
			code,
			code_verifier: codeVerifier,
			grant_type: 'authorization_code',
			redirect_uri: redirectUri,
			scope,
		});
		if (clientSecret) body.set('client_secret', clientSecret);

		const res = await fetch(this.tokenEndpoint, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body,
		});
		if (!res.ok) {
			const text = await res.text().catch(() => '');
			throw new Error(`token exchange failed: ${res.status} ${text}`);
		}
		const json = (await res.json()) as TokenResponse;

		let claims: unknown = {};
		if (this.claimsMode === 'id_token') {
			if (typeof json.id_token !== 'string') throw new Error('id_token_missing');

			const decoded = this.parseJwt(json.id_token) as Record<string, unknown>;
			claims = decoded;

			const issuer = (cfg.issuer ?? this.defaultIssuer) || '';

			// iss
			if (typeof decoded.iss === 'string' && decoded.iss !== issuer) {
				throw new Error('bad_issuer');
			}

			// aud (string or string[])
			const aud = decoded.aud;
			const okAud = (typeof aud === 'string' && aud === cfg.clientId) || (Array.isArray(aud) && aud.includes(cfg.clientId));
			if (!okAud) throw new Error('bad_audience');

			// exp
			const exp = decoded.exp;
			const now = Math.floor(Date.now() / 1000);
			if (typeof exp === 'number' && now >= exp) throw new Error('id_token_expired');
		} else if (this.claimsMode === 'userinfo') {
			if (!this.userInfoEndpoint || typeof json.access_token !== 'string') {
				throw new Error('userinfo_unavailable');
			}
			const info = await this.fetchUserInfo(this.userInfoEndpoint, json.access_token);
			claims = info.claims;
		} else {
			throw new Error('claims_unavailable');
		}

		const norm = this.normalize(claims);
		if (!norm.email) throw new Error('email_required');
		if (!norm.subject) throw new Error('missing_subject');

		const issuer = (cfg.issuer ?? this.defaultIssuer) || '';
		return {
			email: norm.email,
			provider: this.id,
			issuer,
			subject: norm.subject,
		};
	}

	protected async fetchUserInfo(userInfoEndpoint: string, accessToken: string): Promise<{ claims: unknown }> {
		const r = await fetch(userInfoEndpoint, { headers: { authorization: `Bearer ${accessToken}` } });
		if (!r.ok) throw new Error(`userinfo failed: ${r.status}`);
		const claims = (await r.json()) as unknown;
		return { claims };
	}

	protected parseJwt(token: string): unknown {
		const [, p] = token.split('.');
		if (!p) return {};

		// base64url -> base64 with padding
		let b64 = p.replace(/-/g, '+').replace(/_/g, '/');
		const pad = b64.length % 4;
		if (pad) b64 += '='.repeat(4 - pad);

		return JSON.parse(atob(b64));
	}
}
