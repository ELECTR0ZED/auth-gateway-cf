import type { ProjectConfig, RouteRule } from "./types";
import { CONFIG } from "../config";
import { RouteMatcher } from "../routing/routeMatcher";
import {
		JwtSessionStrategy,
		DurableObjectSessionStrategy,
		type SessionStrategy,
		type Session,
} from "../sessions";
import { ProviderRegistry } from "../providers";
import { attachSignedUser, stripUser } from "../utils/propagation";
import {
	makePkceState,
	saveShortState,
	consumeShortState,
} from "../auth/pkceState";

export class Gateway {
	constructor(private env: Env, private cfg: ProjectConfig = CONFIG) {}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		// 1) Auth endpoints centrally handled here
		if (/^\/auth(\/|$)/.test(url.pathname)) {
			return this.handleAuthRoutes(request);
		}

		// 2) Route matching
		const rule = new RouteMatcher(this.cfg.routes).match(url, request.method);
		if (!rule) {
			return new Response("Route not configured", { status: 501 });
		}

		// 3) Session resolution
		const strat = this.makeSessionStrategy();
		const { session, accessJwt } = await strat.resolve(request, this.env, this.cfg);

		// 4) Authorization
		if (rule.auth === "required" && !session) {
			const returnTo = encodeURIComponent(url.pathname + url.search);
			return Response.redirect(
				`${this.cfg.publicBaseUrl}/auth/login?returnTo=${returnTo}`,
				302
			);
		}

		// 5) Forward to FE or API via service bindings, with signed user + short-lived access token
		const headers = new Headers(request.headers);
		if (session) await attachSignedUser(headers, session, this.cfg, this.env);
		else stripUser(headers, this.cfg);
		if (accessJwt) headers.set("X-Access-Token", accessJwt);

		const target = rule.service;

		if (!target) {
			// Misconfigured route or missing binding
			return new Response(`Bad route: service binding not available`, { status: 502 });
		}

		const fwdReq = new Request(new URL(url.pathname + url.search, "http://internal"), {
			method: request.method,
			headers,
			body: request.body,
			redirect: "manual",
			// @ts-expect-error – Workers streaming bodies
			duplex: "half",
		});
		return target.fetch(fwdReq);
	}

	private makeSessionStrategy(): SessionStrategy {
		if (this.cfg.session.kind === "jwt")
			return new JwtSessionStrategy(this.cfg.session);
		if (this.cfg.session.kind === "durableObject")
			return new DurableObjectSessionStrategy(this.cfg.session);
		// Fallback
		return new JwtSessionStrategy({
			kind: "jwt",
			cookieName: "__Host-session",
			expMinutes: 15,
			jwtSecretEnv: "AUTH_JWT_SECRET",
		});
	}

	private async handleAuthRoutes(request: Request): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname === "/auth/login") {
			const { impl, cfg } = this.pickProvider(url.searchParams.get("provider") ?? undefined);
			const { state, codeChallenge, verifier } = await makePkceState();
			await saveShortState(this.env.AUTH_KV, state, verifier, 300);
			const loginUrl = impl.loginURL(
				cfg,
				this.cfg.publicBaseUrl,
				state,
				codeChallenge,
				url.searchParams.get("returnTo") ?? undefined
			);
			return Response.redirect(loginUrl, 302);
		}

		if (url.pathname === "/auth/callback") {
			const { impl, cfg } = this.pickProvider(url.searchParams.get("provider") ?? undefined);
			const code = url.searchParams.get("code")!;
			const { verifier, returnTo } = await consumeShortState(
				this.env.AUTH_KV,
				url.searchParams.get("state")!
			);
			const redirectUri = `${this.cfg.publicBaseUrl}/auth/callback`;
			const res = await impl.exchangeCode(cfg, this.env, code, verifier, redirectUri);


			// Issue session cookie (JWT or DO) and optional access token cookie
			const strat = this.makeSessionStrategy();
			const response = new Response(null, {
				status: 302,
				headers: { Location: returnTo || "/" },
			});
			const issued = await strat.issue?.(res.session, this.env, this.cfg);
			if (issued?.cookie) response.headers.append("Set-Cookie", issued.cookie);
			if (issued?.accessJwt)
				response.headers.append(
					"Set-Cookie",
					`__Host-access=${issued.accessJwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`
				);
			return response;
		}

		if (url.pathname === "/auth/logout") {
			const strat = this.makeSessionStrategy();
			const r = new Response(null, {
				status: 302,
				headers: { Location: "/" },
			});
			const cleared = strat.clear?.(this.env, this.cfg);
			if (cleared?.cookie) r.headers.append("Set-Cookie", cleared.cookie);
			return r;
		}

		return new Response("Not Found", { status: 404 });
	}

	private pickProvider(explicit?: string) {
		const id =
			explicit ||
			this.cfg.defaultProvider ||
			this.cfg.providers.find((p) => p.enabled)?.id;

		const cfg = this.cfg.providers.find((p) => p.id === id && p.enabled);
		if (!cfg) throw new Error("No provider available");

		const impl = ProviderRegistry[cfg.id];
		if (!impl) throw new Error(`No adapter for provider ${cfg.id}`);

		// Return instance + its config separately (no spreading!)
		return { impl, cfg };
	}
}