import type { ProviderConfig, NormalizedClaims } from '../types';
import { AuthProvider } from './baseProvider';

/** Narrow claim shapes we expect from Google for type-safe normalize(). */
type GoogleJwtClaims = {
	sub: string;
	email?: string;
	email_verified?: boolean;
};

type GoogleUserInfo = {
	sub: string;
	email?: string;
};

export class GoogleProvider extends AuthProvider {
	constructor() {
		super({
			id: 'google',
			authorizeEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
			tokenEndpoint: 'https://oauth2.googleapis.com/token',
			defaultIssuer: 'https://accounts.google.com',
			defaultScope: 'openid email profile',
			userInfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
			claimsMode: 'id_token',
		});
	}

	/** Providers must supply a normalize() — no `any` needed. */
	protected normalize(claims: unknown): NormalizedClaims {
		// We accept either ID token payload or userinfo payload
		const c = claims as Partial<GoogleJwtClaims & GoogleUserInfo> | null | undefined;

		const subject = typeof c?.sub === 'string' ? c.sub : '';
		const email = typeof c?.email === 'string' ? c.email : '';

		return { email, subject };
	}

	// (Optional) If you need provider-specific scope overrides per cfg:
	protected override getDefaultScope(cfg: ProviderConfig): string {
		return cfg.scope ?? 'openid email profile';
	}
}
