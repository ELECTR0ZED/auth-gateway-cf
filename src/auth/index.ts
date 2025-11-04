import type { ProjectConfig, UserStore, SessionStrategy } from '../types';
import { makePkceState, saveShortState, consumeShortState } from './pkceState';
import { ProviderRegistry } from '../providers';

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
		const url = new URL(request.url);
		if (!/^\/auth(\/|$)/.test(url.pathname)) {
			return new Response('Not Found', { status: 404 });
		}

		switch (url.pathname) {
			case '/auth/login':
			case '/auth/link':
				return this.loginOrLink(request, url);
			case '/auth/callback':
				return this.callback(request, url);
			case '/auth/logout':
				return this.logout();
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
		const { impl, cfg } = this.pickProvider(url.searchParams.get('provider') ?? undefined);
		const returnTo = url.searchParams.get('returnTo') ?? undefined;

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
		const { impl, cfg } = this.pickProvider(providerParam);
		const code = url.searchParams.get('code')!;
		const state = url.searchParams.get('state')!;
		const { verifier, info } = await consumeShortState(this.cfg.userStore.shortStateKV, state);

		const redirectUri = `${this.cfg.publicBaseUrl}/auth/callback`;
		const identity = await impl.exchangeCode(cfg, this.env, code, verifier, redirectUri);

		const resolved = await this.strat.resolve(request, this.env);
		const activeSession = resolved.session;

		if (!identity.email) {
			return this.redirectError('email_required', info.returnTo);
		}

		if (info.mode === 'link') {
			if (!activeSession) {
				return this.redirectError('link_requires_login', info.returnTo);
			}
			try {
				await this.store.addIdentityToUser(activeSession.userId, {
					provider: identity.provider,
					issuer: identity.issuer,
					subject: identity.subject,
				});
			} catch (e: unknown) {
				const code = (e as Error)?.message === 'identity_taken' ? 'identity_taken' : 'link_failed';
				return this.redirectError(code, info.returnTo);
			}
			return new Response(null, {
				status: 302,
				headers: { Location: info.returnTo || '/' },
			});
		}

		// login / signup
		const byIdentity = await this.store.findUserIdByIdentity(identity.issuer, identity.subject);
		if (byIdentity) {
			const response = new Response(null, {
				status: 302,
				headers: { Location: info.returnTo || '/' },
			});
			const issued = await this.strat.issue?.({ userId: byIdentity, email: identity.email }, this.env);
			if (issued?.cookie) response.headers.append('Set-Cookie', issued.cookie);
			if (issued?.accessJwt)
				response.headers.append(
					'Set-Cookie',
					`__Host-access=${issued.accessJwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`,
				);
			return response;
		}

		const email = identity.email;
		const byEmail = await this.store.findUserIdByEmail(email);
		if (byEmail) {
			return this.redirectError('account_exists', info.returnTo);
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
			return this.redirectError(code, info.returnTo);
		}

		const response = new Response(null, {
			status: 302,
			headers: { Location: info.returnTo || '/' },
		});
		const issued = await this.strat.issue?.({ userId, email }, this.env);
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
		const id = explicit || this.cfg.defaultProvider || this.cfg.providers.find((p) => p.enabled)?.id;

		const cfg = this.cfg.providers.find((p) => p.id === id && p.enabled);
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
}
