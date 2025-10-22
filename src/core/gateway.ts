import type { ProjectConfig, UserStore, SessionStrategy } from '../types';
import { CONFIG } from '../config';
import { RouteMatcher } from '../routing/routeMatcher';
import { JwtSessionStrategy, DurableObjectSessionStrategy } from '../sessions';
import { ProviderRegistry } from '../providers';
import { attachSignedUser, stripUser } from '../utils/propagation';
import { makePkceState, saveShortState, consumeShortState } from '../auth/pkceState';
import { makeUserStore } from '../stores';

export class Gateway {
	private store: UserStore;

	constructor(
		private env: Env,
		private cfg: ProjectConfig = CONFIG,
	) {
		this.store = makeUserStore(cfg.userStore);
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		if (/^\/auth(\/|$)/.test(url.pathname)) {
			return this.handleAuthRoutes(request);
		}

		const rule = new RouteMatcher(this.cfg.routes).match(url, request.method);
		if (!rule) {
			return new Response('Route not configured', { status: 501 });
		}

		const strat = this.makeSessionStrategy();
		const { session, accessJwt } = await strat.resolve(request, this.env);

		if (rule.auth === 'required' && !session) {
			const returnTo = encodeURIComponent(url.pathname + url.search);
			return Response.redirect(`${this.cfg.publicBaseUrl}/auth/login?returnTo=${returnTo}`, 302);
		}

		const headers = new Headers(request.headers);
		if (session) await attachSignedUser(headers, session, this.cfg, this.env);
		else stripUser(headers, this.cfg);
		if (accessJwt) headers.set('X-Access-Token', accessJwt);

		const target = rule.service;
		if (!target) {
			return new Response(`Bad route: service binding not available`, { status: 502 });
		}

		const fwdReq = new Request(new URL(url.pathname + url.search, 'http://internal'), {
			method: request.method,
			headers,
			body: request.body,
			redirect: 'manual',
			// @ts-expect-error – Workers streaming bodies
			duplex: 'half',
		});
		return target.fetch(fwdReq);
	}

	private makeSessionStrategy(): SessionStrategy {
		if (this.cfg.session.kind === 'jwt') return new JwtSessionStrategy(this.cfg.session);
		if (this.cfg.session.kind === 'durableObject') return new DurableObjectSessionStrategy(this.cfg.session);
		return new JwtSessionStrategy({
			kind: 'jwt',
			cookieName: '__Host-session',
			expMinutes: 15,
			jwtSecretEnv: 'AUTH_JWT_SECRET',
		});
	}

	private async handleAuthRoutes(request: Request): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname === '/auth/login' || url.pathname === '/auth/link') {
			const mode = url.pathname.endsWith('/link') ? 'link' : 'login';
			const { impl, cfg } = this.pickProvider(url.searchParams.get('provider') ?? undefined);
			const returnTo = url.searchParams.get('returnTo') ?? undefined;

			const strat = this.makeSessionStrategy();
			const { session } = await strat.resolve(request, this.env);

			if (mode === 'link' && !session) {
				const rt = encodeURIComponent(returnTo ?? '/');
				return Response.redirect(`${this.cfg.publicBaseUrl}/auth/login?returnTo=${rt}`, 302);
			}

			const { state, codeChallenge, verifier } = await makePkceState();
			await saveShortState(this.env.AUTH_KV as unknown as KVNamespace, state, verifier, 300, {
				mode,
				returnTo,
				provider: cfg.id,
			});

			const loginUrl = impl.loginURL(cfg, this.cfg.publicBaseUrl, state, codeChallenge, returnTo);
			return Response.redirect(loginUrl, 302);
		}

		if (url.pathname === '/auth/callback') {
			const providerParam = url.searchParams.get('provider') ?? undefined;
			const { impl, cfg } = this.pickProvider(providerParam);
			const code = url.searchParams.get('code')!;
			const { verifier, info } = await consumeShortState(this.env.AUTH_KV as unknown as KVNamespace, url.searchParams.get('state')!);
			const redirectUri = `${this.cfg.publicBaseUrl}/auth/callback`;
			const identity = await impl.exchangeCode(cfg, this.env, code, verifier, redirectUri);

			const strat = this.makeSessionStrategy();
			const resolved = await strat.resolve(request, this.env);
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
				return Response.redirect(info.returnTo || '/', 302);
			}

			const byIdentity = await this.store.findUserIdByIdentity(identity.issuer, identity.subject);
			if (byIdentity) {
				const response = new Response(null, { status: 302, headers: { Location: info.returnTo || '/' } });
				const issued = await strat.issue?.({ userId: byIdentity, email: identity.email }, this.env);
				if (issued?.cookie) response.headers.append('Set-Cookie', issued.cookie);
				if (issued?.accessJwt)
					response.headers.append(
						'Set-Cookie',
						`__Host-access=${issued.accessJwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`,
					);
				return response;
			}

			const emailLower = identity.email.trim().toLowerCase();
			const byEmail = await this.store.findUserIdByEmail(emailLower);
			if (byEmail) {
				return this.redirectError('account_exists', info.returnTo);
			}

			let userId: string;
			try {
				userId = await this.store.createUserWithIdentity(emailLower, {
					provider: identity.provider,
					issuer: identity.issuer,
					subject: identity.subject,
				});
			} catch (e: unknown) {
				const code = (e as Error)?.message === 'account_exists' ? 'account_exists' : 'signup_failed';
				return this.redirectError(code, info.returnTo);
			}

			const response = new Response(null, { status: 302, headers: { Location: info.returnTo || '/' } });
			const issued = await strat.issue?.({ userId, email: emailLower }, this.env);
			if (issued?.cookie) response.headers.append('Set-Cookie', issued.cookie);
			if (issued?.accessJwt)
				response.headers.append(
					'Set-Cookie',
					`__Host-access=${issued.accessJwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`,
				);
			return response;
		}

		if (url.pathname === '/auth/logout') {
			const strat = this.makeSessionStrategy();
			const r = new Response(null, {
				status: 302,
				headers: { Location: '/' },
			});
			const cleared = strat.clear?.();
			if (cleared?.cookie) r.headers.append('Set-Cookie', cleared.cookie);
			return r;
		}

		return new Response('Not Found', { status: 404 });
	}

	private pickProvider(explicit?: string) {
		const id = explicit || this.cfg.defaultProvider || this.cfg.providers.find((p) => p.enabled)?.id;

		const cfg = this.cfg.providers.find((p) => p.id === id && p.enabled);
		if (!cfg) throw new Error('No provider available');

		const impl = ProviderRegistry[cfg.id];
		if (!impl) throw new Error(`No adapter for provider ${cfg.id}`);

		return { impl, cfg };
	}

	private redirectError(code: string, returnTo?: string) {
		if (returnTo) {
			const sep = returnTo.includes('?') ? '&' : '?';
			return Response.redirect(`${returnTo}${sep}auth_error=${code}`, 302);
		}
		return new Response(null, { status: 302, headers: { Location: `/${'?auth_error=' + code}` } });
	}
}
