import type { ProjectConfig, UserStore, SessionStrategy, Session, ProviderConfig } from '../types';
import { makePkceState, saveShortState, consumeShortState } from './pkceState';
import { ProviderRegistry } from '../providers';
import { normEmail } from '../utils/helpers';
import { safeReturnTo } from '../utils/returnTo';
import { json } from '../utils/http';
import { makeCsrfToken, csrfCookie, sameOrigin, requireCsrfJson } from '../utils/csrf';
import {
	getPeppers,
	hashPassword,
	verifyPasswordWithPepperRotation,
	needsRehash,
	verifyPassword,
	getFakeStoredHash,
} from '../utils/passwords';
import { AuthProvider } from '../providers/baseProvider';
import { getPasswordPolicy, validatePassword } from '../utils/passwordPolicy';

export class AuthRouter {
	constructor(
		private cfg: ProjectConfig,
		private env: Env,
		private store: UserStore,
		private strat: SessionStrategy,
	) {}

	/**
	 * Handles incoming authentication requests.
	 *
	 * @async
	 * @param {Request} request
	 * @returns {Promise<Response>}
	 */
	async handle(request: Request): Promise<Response> {
		if (!this.authFeatureEnabled()) {
			return new Response('Not Found', { status: 404 });
		}
		const url = new URL(request.url);
		if (!/^\/auth(\/|$)/.test(url.pathname)) {
			return new Response('Not Found', { status: 404 });
		}

		switch (url.pathname) {
			case '/auth/login':
			case '/auth/signin':
			case '/auth/link':
				if (!this.oauthEnabled()) return new Response('Not Found', { status: 404 });
				return this.loginOrLink(request, url);
			case '/auth/callback':
				if (!this.oauthEnabled()) return new Response('Not Found', { status: 404 });
				return this.callback(request, url);
			case '/auth/logout':
				return this.logout();
			case '/auth/csrf':
				if (!this.passwordEnabled()) return new Response('Not Found', { status: 404 });
				return this.csrf();
			case '/auth/password/signup':
			case '/auth/password/register':
				if (!this.passwordEnabled()) return new Response('Not Found', { status: 404 });
				return this.passwordRegister(request, url);
			case '/auth/password/login':
				if (!this.passwordEnabled()) return new Response('Not Found', { status: 404 });
				return this.passwordLogin(request, url);
			case '/auth/password/change':
				if (!this.passwordEnabled()) return new Response('Not Found', { status: 404 });
				return this.passwordChange(request);
			default:
				return new Response('Not Found', { status: 404 });
		}
	}

	/**
	 * Handles login or linking of new oauth providers.
	 *
	 * @private
	 * @async
	 * @param {Request} request
	 * @param {URL} url
	 * @returns {Promise<Response>}
	 */
	private async loginOrLink(request: Request, url: URL): Promise<Response> {
		const mode = url.pathname.endsWith('/link') ? 'link' : 'login';

		let picked: { impl: AuthProvider; cfg: ProviderConfig };
		try {
			picked = this.pickProvider(url.searchParams.get('provider') ?? undefined);
		} catch {
			return this.redirectError('provider_unavailable', url.searchParams.get('returnTo') ?? undefined);
		}
		const { impl, cfg } = picked;

		const rawReturnTo = url.searchParams.get('returnTo') ?? undefined;
		const returnTo = safeReturnTo(rawReturnTo, this.cfg.publicBaseUrl);

		const { session } = await this.strat.resolve(request, this.env);

		if (mode === 'link' && !session) {
			const rt = encodeURIComponent(returnTo ?? '/');
			return Response.redirect(`${this.cfg.publicBaseUrl}/auth/login?returnTo=${rt}`, 302);
		}

		const { state, codeChallenge, verifier } = await makePkceState();
		await saveShortState(this.cfg.userStore.shortStateKV, state, verifier, 300, {
			mode,
			returnTo,
			provider: cfg.id,
		});

		const loginUrl = impl.loginURL(cfg, this.cfg.publicBaseUrl, state, codeChallenge);
		return Response.redirect(loginUrl, 302);
	}

	/**
	 * Handles the OAuth callback.
	 *
	 * @private
	 * @async
	 * @param {Request} request
	 * @param {URL} url
	 * @returns {Promise<Response>}
	 */
	private async callback(request: Request, url: URL): Promise<Response> {
		const providerParam = url.searchParams.get('provider') ?? undefined;
		const returnTo = safeReturnTo(url.searchParams.get('returnTo') ?? undefined, this.cfg.publicBaseUrl);

		let picked: { impl: AuthProvider; cfg: ProviderConfig };
		try {
			picked = this.pickProvider(providerParam);
		} catch {
			return this.redirectError('provider_unavailable', returnTo);
		}
		const { impl, cfg } = picked;

		const code = url.searchParams.get('code')!;
		const state = url.searchParams.get('state')!;
		const { verifier, info } = await consumeShortState(this.cfg.userStore.shortStateKV, state);
		const shortStateReturnTo = safeReturnTo(info.returnTo, this.cfg.publicBaseUrl);

		const redirectUri = `${this.cfg.publicBaseUrl}/auth/callback`;
		const identity = await impl.exchangeCode(cfg, this.env, code, verifier, redirectUri);

		const resolved = await this.strat.resolve(request, this.env);
		const activeSession = resolved.session;

		const email = normEmail(identity.email);
		if (!email) {
			return this.redirectError('email_required', shortStateReturnTo);
		}

		if (info.mode === 'link') {
			if (!activeSession) {
				return this.redirectError('link_requires_login', shortStateReturnTo);
			}
			try {
				await this.store.addIdentityToUser(activeSession.userId, {
					provider: identity.provider,
					issuer: identity.issuer,
					subject: identity.subject,
				});
			} catch (e: unknown) {
				const code = (e as Error)?.message === 'identity_taken' ? 'identity_taken' : 'link_failed';
				return this.redirectError(code, shortStateReturnTo);
			}
			return new Response(null, {
				status: 302,
				headers: { Location: shortStateReturnTo || '/' },
			});
		}

		// login / signup
		const byIdentity = await this.store.findUserIdByIdentity(identity.issuer, identity.subject);
		if (byIdentity) {
			const response = new Response(null, {
				status: 302,
				headers: { Location: shortStateReturnTo || '/' },
			});
			const systemRoles = await this.store.getUserRoles(byIdentity);
			const issued = await this.strat.issue?.({ userId: byIdentity, email: email, systemRoles }, this.env);
			if (issued?.cookie) response.headers.append('Set-Cookie', issued.cookie);
			if (issued?.accessJwt)
				response.headers.append(
					'Set-Cookie',
					`__Host-access=${issued.accessJwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`,
				);
			return response;
		}

		const byEmail = await this.store.findUserIdByEmail(email);
		if (byEmail) {
			return this.redirectError('account_exists', shortStateReturnTo);
		}

		let userId: string;
		try {
			userId = await this.store.createUserWithIdentity(email, {
				provider: identity.provider,
				issuer: identity.issuer,
				subject: identity.subject,
			});
		} catch (e: unknown) {
			const code = (e as Error)?.message === 'account_exists' ? 'account_exists' : 'signup_failed';
			return this.redirectError(code, shortStateReturnTo);
		}

		const response = new Response(null, {
			status: 302,
			headers: { Location: shortStateReturnTo || '/' },
		});
		const systemRoles = await this.store.getUserRoles(userId);
		await this.applyIssuedCookies(response, { userId, email: identity.email, systemRoles });
		return response;
	}

	/**
	 * Handles user logout.
	 *
	 * @private
	 * @returns {Response}
	 */
	private logout(): Response {
		const r = new Response(null, {
			status: 302,
			headers: { Location: '/' },
		});
		const cleared = this.strat.clear?.();
		if (cleared?.cookie) r.headers.append('Set-Cookie', cleared.cookie);
		return r;
	}

	/**
	 * Selects the OAuth provider implementation and configuration.
	 *
	 * @private
	 * @param {?string} [explicit]
	 * @returns {{ impl: any; cfg: any; }}
	 */
	private pickProvider(explicit?: string) {
		const providers = this.cfg.providers ?? [];
		const id = explicit || this.cfg.defaultProvider || providers.find((p) => p.enabled)?.id;

		const cfg = providers.find((p) => p.id === id && p.enabled);
		if (!cfg) throw new Error('No provider available');

		const impl = ProviderRegistry[cfg.id];
		if (!impl) throw new Error(`No adapter for provider ${cfg.id}`);

		return { impl, cfg };
	}

	/**
	 * Handles error redirection during auth flow.
	 *
	 * @private
	 * @param {string} code
	 * @param {?string} [returnTo]
	 * @returns {*}
	 */
	private redirectError(code: string, returnTo?: string) {
		if (returnTo) {
			const sep = returnTo.includes('?') ? '&' : '?';
			return Response.redirect(`${returnTo}${sep}auth_error=${code}`, 302);
		}
		return new Response(null, {
			status: 302,
			headers: { Location: `/${'?auth_error=' + code}` },
		});
	}

	private csrf(): Response {
		const token = makeCsrfToken();
		const res = json({ csrf: token });
		res.headers.append('Set-Cookie', csrfCookie(token));
		return res;
	}

	private async passwordRegister(request: Request, url: URL): Promise<Response> {
		if (!this.passwordSignupAllowed()) {
			return new Response('Not Found', { status: 404 });
		}

		if (!sameOrigin(request, this.cfg.publicBaseUrl)) {
			return new Response('Forbidden', { status: 403 });
		}

		const parsed = await requireCsrfJson<Record<string, unknown>>(request);
		if (!parsed.ok) return json({ error: parsed.code }, { status: 400 });

		const emailRaw = parsed.body.email;
		const password = parsed.body.password;

		if (typeof emailRaw !== 'string' || typeof password !== 'string') {
			return json({ error: 'invalid_request' }, { status: 400 });
		}

		const email = normEmail(emailRaw);

		const policy = getPasswordPolicy(this.cfg.passwordAuth?.policy);
		const check = validatePassword(password, policy);
		if (!check.ok) {
			// Keep generic unless you explicitly want to expose reasons
			return json({ error: 'password_policy_violation' }, { status: 400 });
		}

		const peppers = getPeppers(this.env, this.pepperEnvName());
		const primaryPepper = peppers[0];
		const passwordHash = await hashPassword(password, primaryPepper ? { pepper: primaryPepper } : undefined);

		let userId: string;
		try {
			userId = await this.store.createUserWithPassword(email, passwordHash);
		} catch (err: unknown) {
			if (err === 'account_exists' || (err instanceof Error && 'code' in err && err.code === 'account_exists')) {
				return json({ error: 'account_exists' }, { status: 400 });
			}

			return json({ error: 'signup_failed' }, { status: 500 });
		}

		const returnTo = safeReturnTo(url.searchParams.get('returnTo') || '/', this.cfg.publicBaseUrl);

		const res = new Response(null, {
			status: 302,
			headers: { Location: returnTo || '/' },
		});

		await this.applyIssuedCookies(res, { userId, email, systemRoles: [] });
		return res;
	}

	private async passwordLogin(request: Request, url: URL): Promise<Response> {
		if (!sameOrigin(request, this.cfg.publicBaseUrl)) {
			return new Response('Forbidden', { status: 403 });
		}

		const parsed = await requireCsrfJson<{ email?: string; password?: string; csrf?: string }>(request);
		if (!parsed.ok) return json({ error: parsed.code }, { status: 400 });

		const emailRaw = parsed.body.email;
		const password = parsed.body.password;

		if (typeof emailRaw !== 'string' || typeof password !== 'string' || password.length < 1) {
			return json({ error: 'invalid_request' }, { status: 400 });
		}

		const email = normEmail(emailRaw);
		const returnTo = url.searchParams.get('returnTo') || '/';

		const row = await this.store.getUserIdByEmailForPassword(email);

		const peppers = getPeppers(this.env, this.pepperEnvName());

		// Reduce timing differences: always verify against some hash
		if (!row) {
			const primaryPepper = peppers[0];
			await verifyPassword(password, getFakeStoredHash(), primaryPepper);
			return json({ error: 'invalid_credentials' }, { status: 401 });
		}

		const storedHash = row.passwordHash;
		const verify = await verifyPasswordWithPepperRotation(password, storedHash, peppers);

		if (!verify.ok) {
			return json({ error: 'invalid_credentials' }, { status: 401 });
		}

		// Rotate pepper/params on successful login
		if (verify.usedPepperIndex !== 0 || needsRehash(row.passwordHash)) {
			const newHash = await hashPassword(password, { pepper: peppers[0] });
			await this.store.setPasswordHash(row.userId, newHash);
		}

		const res = new Response(null, {
			status: 302,
			headers: { Location: returnTo || '/' },
		});
		const systemRoles = await this.store.getUserRoles(row.userId);
		await this.applyIssuedCookies(res, { userId: row.userId, email, systemRoles });
		return res;
	}

	private async passwordChange(request: Request): Promise<Response> {
		if (!sameOrigin(request, this.cfg.publicBaseUrl)) {
			return new Response('Forbidden', { status: 403 });
		}

		const resolved = await this.strat.resolve(request, this.env);
		const session = resolved.session;
		if (!session) return json({ error: 'unauthorized' }, { status: 401 });

		const parsed = await requireCsrfJson<{ currentPassword?: string; newPassword?: string; csrf?: string }>(request);
		if (!parsed.ok) return json({ error: parsed.code }, { status: 400 });

		const currentPassword = parsed.body.currentPassword;
		const newPassword = parsed.body.newPassword;

		if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
			return json({ error: 'invalid_request' }, { status: 400 });
		}
		const policy = this.passwordPolicy();
		const check = validatePassword(newPassword, policy);

		if (!check.ok) {
			return json({ error: 'password_policy_violation' }, { status: 400 });
		}

		const existingHash = await this.store.getPasswordHashByUserId(session.userId);
		if (!existingHash) return json({ error: 'password_not_set' }, { status: 400 });

		const peppers = getPeppers(this.env, this.pepperEnvName());
		const verify = await verifyPasswordWithPepperRotation(currentPassword, existingHash, peppers);
		if (!verify.ok) return json({ error: 'invalid_credentials' }, { status: 401 });

		const newHash = await hashPassword(newPassword, { pepper: peppers[0] });
		await this.store.setPasswordHash(session.userId, newHash);

		// Rotate session after password change (recommended)
		const res = json({ ok: true }, { status: 200 });
		await this.applyIssuedCookies(res, { userId: session.userId, email: session.email, systemRoles: session.systemRoles });
		return res;
	}

	private async applyIssuedCookies(res: Response, session: Session) {
		const issued = await this.strat.issue?.(session, this.env);
		if (issued?.cookie) res.headers.append('Set-Cookie', issued.cookie);
		if (issued?.accessJwt) {
			res.headers.append('Set-Cookie', `__Host-access=${issued.accessJwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`);
		}
	}

	private oauthEnabled(): boolean {
		return this.cfg.oAuth?.enabled !== false; // default ON for backwards compatibility
	}

	private passwordEnabled(): boolean {
		return this.cfg.passwordAuth?.enabled === true;
	}

	private authFeatureEnabled(): boolean {
		return this.oauthEnabled() || this.passwordEnabled();
	}

	private pepperEnvName(): string {
		return this.cfg.passwordAuth?.pepperEnv ?? 'PASSWORD_PEPPERS';
	}

	private passwordPolicy() {
		return getPasswordPolicy(this.cfg.passwordAuth?.policy);
	}

	private passwordSignupAllowed(): boolean {
		return this.cfg.passwordAuth?.allowSignup === true;
	}
}
