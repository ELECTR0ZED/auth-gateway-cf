import type { ProviderConfig } from '../types';
import { AuthProvider } from './baseProvider';

export class GoogleProvider extends AuthProvider {
	id = 'google' as const;

	protected getAuthorizeEndpoint(): string {
		return 'https://accounts.google.com/o/oauth2/v2/auth';
	}

	protected getTokenEndpoint(): string {
		return 'https://oauth2.googleapis.com/token';
	}

	protected getDefaultIssuer(): string {
		return 'https://accounts.google.com';
	}

	protected getDefaultScope(cfg: ProviderConfig): string {
		return cfg.scope ?? 'openid email profile';
	}

	protected async fetchUserInfo(_: ProviderConfig, accessToken: string): Promise<{ claims: any }> {
		const r = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
			headers: { authorization: `Bearer ${accessToken}` },
		});
		if (!r.ok) throw new Error(`userinfo failed: ${r.status}`);
		return { claims: await r.json() };
	}
}
