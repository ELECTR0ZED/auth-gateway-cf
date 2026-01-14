import type { ProjectConfig, SessionStrategy } from '../types';
import { RouteMatcher } from '../routing/routeMatcher';
import { makeSessionStrategy } from '../sessions';
import { attachSignedUser, stripUser } from '../utils/propagation';
import { AuthRouter } from '../auth';
import { makeUserStore } from '../stores';
import { hasAllRoles, hasAnyRole } from '../utils/roles';
import { safeReturnTo } from '../utils/returnTo';

export class Gateway {
	private auth: AuthRouter;
	private strat: SessionStrategy;

	constructor(
		private env: Env,
		private cfg: ProjectConfig,
	) {
		const store = makeUserStore(cfg.userStore);
		this.strat = makeSessionStrategy(cfg.session);
		this.auth = new AuthRouter(cfg, env, store, this.strat);
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		// If the request is for auth, delegate to AuthRouter
		if (/^\/auth(\/|$)/.test(url.pathname)) {
			return this.auth.handle(request);
		}

		// Match route
		const rule = new RouteMatcher(this.cfg.routes).match(url, request.method);
		if (!rule) {
			return new Response('Route not configured', { status: 501 });
		}

		// Check for existing session
		const { session, accessJwt } = await this.strat.resolve(request, this.env);

		// Enforce auth if route requires it
		if (rule.auth === 'required') {
			if (!this.auth.authFeatureEnabled()) {
				return new Response('Authentication is disabled', { status: 501 });
			}
			if (!session) {
				const returnTo = safeReturnTo(request.url, this.cfg.publicBaseUrl);
				return this.auth.createUnauthenticatedRedirect(request.url, returnTo);
			}

			if (rule.requireRolesAll && !hasAllRoles(session.systemRoles, rule.requireRolesAll)) {
				return new Response('Forbidden', { status: 403 });
			}

			if (rule.requireRolesAny && !hasAnyRole(session.systemRoles, rule.requireRolesAny)) {
				return new Response('Forbidden', { status: 403 });
			}
		}

		// Prepare forwarded request with appropriate headers
		const headers = new Headers(request.headers);
		if (session) await attachSignedUser(headers, session, this.cfg, this.env);
		else stripUser(headers, this.cfg);
		if (accessJwt) headers.set('X-Access-Token', accessJwt);

		// Get target service binding
		const target = rule.service;
		if (!target) {
			return new Response(`Bad route: service binding not available`, { status: 502 });
		}

		// Forward the request to the internal service
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
}
