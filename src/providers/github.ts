import type { ProviderConfig } from "../core/types";
import type { Session } from "../sessions";
import { AuthProvider } from "./baseProvider";

type GitHubUser = {
	id: number;
	login: string;
	name?: string;
	email?: string | null; // often null unless scope 'user:email' or public email set
	[k: string]: unknown;
};
type GitHubEmail = { email: string; primary: boolean; verified: boolean; visibility: string | null };

export class GitHubProvider extends AuthProvider {
	id = "github" as const;

	protected getAuthorizeEndpoint(_: ProviderConfig): string {
		return "https://github.com/login/oauth/authorize";
	}

	protected getTokenEndpoint(_: ProviderConfig): string {
		return "https://github.com/login/oauth/access_token";
	}

	protected getDefaultScope(cfg: ProviderConfig): string {
		// Request user:email so we can fetch primary email
		return cfg.scope ?? "read:user user:email";
	}

	// GitHub does NOT issue id_token; override exchangeCode to set Accept header
	async exchangeCode(
		cfg: ProviderConfig,
		env: Env,
		code: string,
		codeVerifier: string, // PKCE is supported for GH Apps/OAuth apps when enabled; unused is fine
		redirectUri: string
	): Promise<{ session: Session; idToken?: string; accessToken?: string; refreshToken?: string }> {
		const clientSecret = this.getClientSecret(env, cfg);
		const body = new URLSearchParams({
			client_id: cfg.clientId,
			code,
			grant_type: "authorization_code",
			redirect_uri: redirectUri,
			// GitHub doesn’t currently require PKCE fields for classic OAuth apps unless configured; omit if not used.
			...(codeVerifier ? { code_verifier: codeVerifier } : {}),
			...(clientSecret ? { client_secret: clientSecret } : {}),
		});

		const res = await fetch(this.getTokenEndpoint(cfg), {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				"accept": "application/json",
			},
			body,
		});
		if (!res.ok) {
			const text = await res.text().catch(() => "");
			throw new Error(`token exchange failed: ${res.status} ${text}`);
		}

		const json = (await res.json()) as { access_token?: string; token_type?: string; scope?: string };
		if (!json.access_token) throw new Error("missing access_token");

		// Fetch user info
		const user = await this.fetchGitHubUser(json.access_token);
		const email = user.email || (await this.fetchPrimaryEmail(json.access_token));
		const claims = { sub: String(user.id), email, login: user.login, name: user.name };

		return {
			session: this.normalize(claims),
			accessToken: json.access_token,
			refreshToken: undefined,
			idToken: undefined,
		};
	}

	protected normalize(claims: any) {
		// Map to your canonical session; GitHub has no roles by default
		return { sub: claims.sub, email: claims.email, roles: [], claims };
	}

	private async fetchGitHubUser(token: string): Promise<GitHubUser> {
		const r = await fetch("https://api.github.com/user", {
			headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json" },
		});
		if (!r.ok) throw new Error(`github user failed: ${r.status}`);
		return (await r.json()) as GitHubUser;
		}

	private async fetchPrimaryEmail(token: string): Promise<string | undefined> {
		const r = await fetch("https://api.github.com/user/emails", {
			headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json" },
		});
		if (!r.ok) return undefined;
		const emails = (await r.json()) as GitHubEmail[];
		const primary = emails.find(e => e.primary && e.verified) || emails[0];
		return primary?.email;
	}
}
