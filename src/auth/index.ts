import type { ProjectConfig, UserStore, SessionStrategy, Session, ProviderConfig } from '../types';
import { makePkceState, saveShortState, consumeShortState } from './pkceState';
import { ProviderRegistry } from '../providers';
import { generateUsername, normEmail, validateEmail } from '../utils/helpers';
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
import { getTurnstileTokenField, verifyTurnstile } from '../utils/turnstile';

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

		// Preliminary checks
		switch (url.pathname) {
			case '/auth/login':
			case '/auth/signin':
			case '/auth/link':
			case '/auth/callback':
				if (!this.oauthEnabled()) return new Response('Not Found', { status: 404 });
				break;
			case '/auth/csrf':
				if (!this.passwordEnabled()) return new Response('Not Found', { status: 404 });
				break;
			case '/auth/password/signup':
			case '/auth/password/register':
			case '/auth/password/login':
			case '/auth/password/signin':
			case '/auth/password/change':
				if (!this.passwordEnabled()) return new Response('Not Found', { status: 404 });
				if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
				break;
		}

		switch (url.pathname) {
			case '/auth/login':
			case '/auth/signin':
			case '/auth/link':
				return this.loginOrLink(request, url);
			case '/auth/callback':
				return this.callback(request, url);
			case '/auth/logout':
				return this.logout();
			case '/auth/csrf':
				return this.csrf();
			case '/auth/password/signup':
			case '/auth/password/register':
				return this.passwordRegister(request, url);
			case '/auth/password/login':
			case '/auth/password/signin':
				return this.passwordLogin(request, url);
			case '/auth/password/change':
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
			return this.redirectError('link_requires_login', returnTo);
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
		if (info.provider && info.provider !== cfg.id) {
			return this.redirectError('provider_mismatch', safeReturnTo(info.returnTo, this.cfg.publicBaseUrl));
		}

		const shortStateReturnTo = safeReturnTo(info.returnTo, this.cfg.publicBaseUrl);
		const successRedirectUrl = this.cfg.oAuth.enabled ? this.cfg.oAuth.successRedirectUrl : undefined;

		const redirectUri = `${this.cfg.publicBaseUrl}/auth/callback`;
		const identity = await impl.exchangeCode(cfg, this.env, code, verifier, redirectUri);

		const resolved = await this.strat.resolve(request, this.env);
		const activeSession = resolved.session;

		const email = normEmail(identity.email);
		if (!email) {
			return this.redirectError('email_required', shortStateReturnTo);
		}

		const byIdentity = await this.store.findUserIdByIdentity(identity.issuer, identity.subject);

		// Sign-up flow
		if (!byIdentity && info.mode !== 'link') {
			const byEmail = await this.store.findUserIdByEmail(email);
			if (byEmail) {
				return this.redirectError('account_exists', shortStateReturnTo);
			}

			let generateUsernameFunc: ((email: string) => string) | undefined = undefined;
			if (this.cfg.overrides?.captureUsername.enabled) {
				if (this.cfg.overrides.captureUsername.required) {
					generateUsernameFunc = this.cfg.overrides?.captureUsername.generateFunction || generateUsername;
				}
			}

			let userId: string;
			try {
				userId = await this.store.createUserWithIdentity(
					email,
					{
						provider: identity.provider,
						issuer: identity.issuer,
						subject: identity.subject,
					},
					generateUsernameFunc,
				);
			} catch (e: unknown) {
				const code = (e as Error)?.message === 'account_exists' ? 'account_exists' : 'signup_failed';
				return this.redirectError(code, shortStateReturnTo);
			}

			// Auto-login after signup if enabled and no further steps required (like email verification or account approval)
			const canAutoLogin = this.canAutoLoginAfterSignup();
			if (!canAutoLogin) {
				const requiresEmailVerification =
					this.cfg.overrides?.emailVerification?.enabled && this.cfg.overrides?.emailVerification?.requiredForLogin;
				const requiresAccountApproval = this.cfg.overrides?.accountApproval?.enabled;
				const redirectUrl = successRedirectUrl || '/';
				const sep = redirectUrl.includes('?') ? '&' : '?';
				return new Response(null, {
					status: 302,
					headers: {
						Location:
							redirectUrl +
							(requiresEmailVerification
								? `${sep}next=verify_email`
								: requiresAccountApproval
									? `${sep}next=awaiting_approval`
									: ''),
					},
				});
			}

			const response = new Response(null, {
				status: 302,
				headers: { Location: shortStateReturnTo || successRedirectUrl || '/' },
			});
			await this.applyIssuedCookies(response, { userId, email, systemRoles: [] });
			return response;
		}

		if (!byIdentity) {
			return this.redirectError('identity_not_found', shortStateReturnTo);
		}

		const checkStates = await this.checkUserStates(byIdentity);
		if (!checkStates.success) {
			return this.redirectError(checkStates.reason, shortStateReturnTo);
		}

		// Link flow
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
				headers: { Location: shortStateReturnTo || successRedirectUrl || '/' },
			});
		}

		// Login flow
		const response = new Response(null, {
			status: 302,
			headers: { Location: shortStateReturnTo || successRedirectUrl || '/' },
		});
		const systemRoles = await this.store.getUserRoles(byIdentity);
		const issued = await this.strat.issue?.({ userId: byIdentity, email: email, systemRoles }, this.env);
		if (issued?.cookie) response.headers.append('Set-Cookie', issued.cookie);
		if (issued?.accessJwt)
			response.headers.append('Set-Cookie', `__Host-access=${issued.accessJwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`);
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
		if (!this.cfg.oAuth.enabled) throw new Error('OAuth is disabled');
		const providers = this.cfg.oAuth.providers ?? [];
		const id = explicit || this.cfg.oAuth.defaultProvider || providers.find((p) => p.enabled)?.id;

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
		const failureRedirectUrl = this.cfg.oAuth.enabled ? this.cfg.oAuth.failureRedirectUrl : undefined;
		if (failureRedirectUrl) {
			const sep = failureRedirectUrl.includes('?') ? '&' : '?';
			return Response.redirect(`${failureRedirectUrl}${sep}auth_error=${code}`, 302);
		}

		if (returnTo) {
			const sep = returnTo.includes('?') ? '&' : '?';
			return Response.redirect(`${returnTo}${sep}auth_error=${code}`, 302);
		}

		return new Response(null, {
			status: 302,
			headers: { Location: `'/'?auth_error=${code}` },
		});
	}

	private csrf(): Response {
		const token = makeCsrfToken();
		const res = json({ csrf: token });
		res.headers.append('Set-Cookie', csrfCookie(token));
		return res;
	}

	private async passwordRegister(request: Request, url: URL): Promise<Response> {
		// Reject if signup is disabled
		if (!this.cfg.passwordAuth.enabled || !this.cfg.passwordAuth.allowSignup) {
			return new Response('Not Found', { status: 404 });
		}

		// Enforce same-origin policy for signup - currently required to read cookies (such as CSRF)
		if (!sameOrigin(request, this.cfg.publicBaseUrl)) {
			return new Response('Forbidden', { status: 403 });
		}

		// Parse and validate request body
		const parsed = await requireCsrfJson<Record<string, unknown>>(request);
		if (!parsed.ok) return json({ error: parsed.code }, { status: 400 });

		// Verify turnstile if enabled, will pass if disabled
		const ts = await this.requireTurnstile(request, parsed.body);
		if (!ts.ok) return json({ error: ts.code }, { status: 401 });

		// Extract fields
		const usernameRaw = parsed.body.username;
		const emailRaw = parsed.body.email;
		const password = parsed.body.password;

		const username = typeof usernameRaw === 'string' ? usernameRaw.trim() : null;

		// Basic validation
		if (typeof emailRaw !== 'string' || typeof password !== 'string' || password.length === 0) {
			return json({ error: 'invalid_request' }, { status: 400 });
		}

		// Conditional username validation
		if (this.cfg.overrides?.captureUsername.enabled) {
			if (this.cfg.overrides.captureUsername.required && (!username || username.length === 0)) {
				return json({ error: 'username_required' }, { status: 400 });
			}
			if (username && username.length < (this.cfg.overrides.captureUsername.minLength || 0)) {
				return json({ error: 'username_too_short' }, { status: 400 });
			}
		}

		// Normalize and validate email
		const email = normEmail(emailRaw);
		const isEmailValid = validateEmail(email);
		if (!isEmailValid) {
			return json({ error: 'invalid_email' }, { status: 400 });
		}

		// Validate password against policy
		const policy = getPasswordPolicy(this.cfg.passwordAuth?.policy);
		const check = validatePassword(password, policy);
		if (!check.ok) {
			// Keep generic unless you explicitly want to expose reasons
			return json({ error: 'password_policy_violation' }, { status: 400 });
		}

		// Hash password with pepper
		const peppers = getPeppers(this.env, this.pepperEnvName());
		const primaryPepper = peppers[0];
		const passwordHash = await hashPassword(password, primaryPepper ? { pepper: primaryPepper } : undefined);

		// Create user account
		let userId: string;
		try {
			userId = await this.store.createUserWithPassword(email, passwordHash, username);
		} catch (err: unknown) {
			const errorMessage = (err as Error).message;
			if (errorMessage === 'account_exists') {
				return json({ error: 'account_exists' }, { status: 400 });
			}

			return json({ error: 'signup_failed' }, { status: 500 });
		}

		// Auto-login after signup if enabled and no further steps required (like email verification or account approval)
		const canAutoLogin = this.canAutoLoginAfterSignup();
		if (!canAutoLogin) {
			return json(
				{
					success: true,
					requiresEmailVerification:
						this.cfg.overrides?.emailVerification?.enabled && this.cfg.overrides?.emailVerification?.requiredForLogin,
					requiresAccountApproval: this.cfg.overrides?.accountApproval?.enabled,
				},
				{ status: 200 },
			);
		}

		// Issue session and redirect to returnTo
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

		const ts = await this.requireTurnstile(request, parsed.body);
		if (!ts.ok) return json({ error: ts.code }, { status: 401 });

		const emailRaw = parsed.body.email;
		const password = parsed.body.password;

		if (typeof emailRaw !== 'string' || typeof password !== 'string' || password.length === 0) {
			return json({ error: 'invalid_request' }, { status: 400 });
		}

		const email = normEmail(emailRaw);
		const returnTo = safeReturnTo(url.searchParams.get('returnTo') || '/', this.cfg.publicBaseUrl);

		const row = await this.store.getUserIdByEmailForPassword(email);

		const peppers = getPeppers(this.env, this.pepperEnvName());
		const primaryPepper = peppers[0];

		// Reduce timing differences: always verify against some hash
		if (!row) {
			await verifyPassword(password, getFakeStoredHash(), primaryPepper);
			return json({ error: 'invalid_credentials' }, { status: 401 });
		}

		const storedHash = row.passwordHash;
		const verify = await verifyPasswordWithPepperRotation(password, storedHash, peppers);

		if (!verify.ok) {
			return json({ error: 'invalid_credentials' }, { status: 401 });
		}

		// Rotate pepper/params on successful login
		if (verify.usedPepperIndex > 0 || needsRehash(row.passwordHash)) {
			try {
				const newHash = await hashPassword(password, primaryPepper ? { pepper: primaryPepper } : undefined);
				await this.store.setPasswordHash(row.userId, newHash);
			} catch (err) {
				console.error('Failed to update password hash during login for user', row.userId, err);
			}
		}

		const checkStates = await this.checkUserStates(row.userId);
		if (!checkStates.success) {
			return json({ error: checkStates.reason }, { status: 403 });
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

		const ts = await this.requireTurnstile(request, parsed.body);
		if (!ts.ok) return json({ error: ts.code }, { status: 401 });

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

	async checkUserStates(
		userId: string,
	): Promise<{ success: true } | { success: false; reason: 'account_disabled' | 'account_unapproved' | 'email_unverified' }> {
		const userStates = await this.store.getUserStates(userId);

		// Reject disabled accounts always
		if (userStates?.is_disabled) {
			return { success: false, reason: 'account_disabled' };
		}

		// Check if approval is enabled and user is unapproved then reject login
		if (this.cfg.overrides?.accountApproval.enabled) {
			if (userStates?.is_approved === false) {
				return { success: false, reason: 'account_unapproved' };
			}
		}

		// Reject login when email verification is enabled, required for login, and the user's email is unverified
		if (this.cfg.overrides?.emailVerification.enabled) {
			if (userStates?.is_email_verified === false && this.cfg.overrides.emailVerification.requiredForLogin) {
				return { success: false, reason: 'email_unverified' };
			}
		}

		return { success: true };
	}

	private async applyIssuedCookies(res: Response, session: Session) {
		const issued = await this.strat.issue?.(session, this.env);
		if (issued?.cookie) res.headers.append('Set-Cookie', issued.cookie);
		if (issued?.accessJwt) {
			res.headers.append('Set-Cookie', `__Host-access=${issued.accessJwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`);
		}
	}

	private oauthEnabled(): boolean {
		return this.cfg.oAuth?.enabled === true;
	}

	private passwordEnabled(): boolean {
		return this.cfg.passwordAuth?.enabled === true;
	}

	authFeatureEnabled(): boolean {
		return this.oauthEnabled() || this.passwordEnabled();
	}

	private pepperEnvName(): string {
		if (!this.cfg.passwordAuth?.enabled) return 'PASSWORD_PEPPERS';
		return this.cfg.passwordAuth?.pepperEnv ?? 'PASSWORD_PEPPERS';
	}

	private passwordPolicy() {
		if (!this.cfg.passwordAuth?.enabled) return getPasswordPolicy();
		return getPasswordPolicy(this.cfg.passwordAuth?.policy);
	}

	private turnstileEnabled(): boolean {
		if (!this.cfg.passwordAuth?.enabled) return false;
		return this.cfg.passwordAuth?.turnstile?.enabled === true;
	}

	private turnstileSecret(): string | null {
		if (!this.cfg.passwordAuth?.enabled) return null;
		if (!this.cfg.passwordAuth?.turnstile?.enabled) return null;
		const key = this.cfg.passwordAuth?.turnstile?.secretEnv;
		if (!key) return null;
		const v = this.env[key];
		return typeof v === 'string' && v.length > 0 ? v : null;
	}

	private turnstileTokenField(): string {
		if (!this.cfg.passwordAuth?.enabled) return 'turnstileToken';
		if (!this.cfg.passwordAuth?.turnstile?.enabled) return 'turnstileToken';
		return getTurnstileTokenField(this.cfg.passwordAuth?.turnstile);
	}

	private async requireTurnstile(request: Request, body: Record<string, unknown>): Promise<{ ok: true } | { ok: false; code: string }> {
		if (!this.turnstileEnabled()) return { ok: true };

		const secret = this.turnstileSecret();
		if (!secret) return { ok: false, code: 'turnstile_misconfigured' };

		const field = this.turnstileTokenField();
		const token = body[field];
		if (typeof token !== 'string' || token.trim().length === 0) {
			return { ok: false, code: 'turnstile_missing' };
		}

		const ip = request.headers.get('CF-Connecting-IP') ?? undefined; // optional
		const result = await verifyTurnstile(token, secret, ip);

		if (!result.ok) return { ok: false, code: result.code };
		return { ok: true };
	}

	private canAutoLoginAfterSignup(): boolean {
		if (!this.cfg.overrides?.autoLoginAfterSignup) return false;

		if (this.cfg.overrides.accountApproval.enabled) return false;

		if (this.cfg.overrides.emailVerification.enabled && this.cfg.overrides.emailVerification.requiredForLogin) {
			return false;
		}

		return true;
	}

	getGlobalUnauthenticatedRedirectUrl(): string {
		return this.cfg.overrides?.globalUnauthenticatedRedirectUrl || '/auth/login';
	}

	createUnauthenticatedRedirect(base: string, returnTo?: string, redirectTo?: string): Response {
		const target = new URL(redirectTo || this.getGlobalUnauthenticatedRedirectUrl(), base);
		if (returnTo) target.searchParams.set('returnTo', returnTo);
		return Response.redirect(target.toString(), 302);
	}
}
