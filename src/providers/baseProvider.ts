import type { ProviderConfig, LoginProviderId, ProviderIdentity, TokenResponse } from '../types';
import { normEmail } from '../utils/helpers';

export abstract class AuthProvider {
	abstract id: LoginProviderId;

	protected abstract getAuthorizeEndpoint(cfg: ProviderConfig): string;
	protected abstract getTokenEndpoint(cfg: ProviderConfig): string;
	protected abstract getDefaultIssuer(cfg: ProviderConfig): string;

	protected getDefaultScope(cfg: ProviderConfig): string {
		return cfg.scope ?? 'openid email profile';
	}

	protected getRedirectUri(baseUrl: string): string {
		return `${baseUrl}/auth/callback`;
	}

	protected getClientSecret(env: Env, cfg: ProviderConfig): string | undefined {
		const key = cfg.clientSecretEnv;
		return key ? env[key] : undefined;
	}

	loginURL(cfg: ProviderConfig, baseUrl: string, state: string, codeChallenge: string): string {
		const authorize = this.getAuthorizeEndpoint(cfg);
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

		return `${authorize}?${qp.toString()}`;
	}

	async exchangeCode(cfg: ProviderConfig, env: Env, code: string, codeVerifier: string, redirectUri: string): Promise<ProviderIdentity> {
		const tokenUrl = this.getTokenEndpoint(cfg);
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

		const res = await fetch(tokenUrl, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body,
		});
		if (!res.ok) {
			const text = await res.text().catch(() => '');
			throw new Error(`token exchange failed: ${res.status} ${text}`);
		}

		const json = (await res.json()) as TokenResponse;

		let claims: any = {};
		if (typeof json.id_token === 'string') {
			claims = this.parseJwt(json.id_token);
		} else if (typeof json.access_token === 'string') {
			const info = await this.fetchUserInfo(cfg, json.access_token);
			claims = info.claims;
		}

		const email = (claims?.email || '').toString();
		if (!email) {
			throw new Error('email_required');
		}

		const issuer = (cfg.issuer ?? this.getDefaultIssuer(cfg)) || '';
		const subject = (claims?.sub || '').toString();
		if (!subject) {
			throw new Error('missing_subject');
		}

		return {
			email: normEmail(email),
			provider: this.id,
			issuer,
			subject,
		};
	}

	protected async fetchUserInfo(cfg: ProviderConfig, accessToken: string): Promise<{ claims: any }> {
		if (!cfg.userInfoUrl) return { claims: {} };
		const r = await fetch(cfg.userInfoUrl, {
			headers: { authorization: `Bearer ${accessToken}` },
		});
		if (!r.ok) throw new Error(`userinfo failed: ${r.status}`);
		const claims = (await r.json()) as any;
		return { claims };
	}

	protected parseJwt(token: string): any {
		const [, p] = token.split('.');
		return JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
	}
}
