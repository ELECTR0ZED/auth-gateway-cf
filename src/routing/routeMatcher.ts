import type { Match, RouteRule } from "../core/types";

export class RouteMatcher {
	constructor(private rules: RouteRule[]) {}

	match(url: URL, method: string): RouteRule | undefined {
		for (const rule of this.rules) {
			const arr = Array.isArray(rule.match) ? rule.match : [rule.match];
			for (const m of arr) {
				if (this.one(m, url, method)) {
					console.log(`Matched route: ${JSON.stringify(rule)}`);
					return rule;
				}
			}
		}
		return undefined;
	}

	private one(m: Match, url: URL, method: string): boolean {
		const okMethod = !m.methods || m.methods.includes(method.toUpperCase());
		if (!okMethod) return false;
		const re = toRegExp(m.path);
		return re.test(url.pathname);
	}
}

function toRegExp(path: string | RegExp): RegExp {
	if (path instanceof RegExp) {
		return path;
	}
	let p = path
		.replace(/[.+^${}()|[\]\\]/g, "\\$&")
		.replace(/\*\*/g, ".*")
		.replace(/\*/g, "[^/]*");
	return new RegExp(`^${p}$`);
}