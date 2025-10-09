import type { PolicyCtx } from "./types";
import type { BasePolicy } from "./basePolicy";
import enforceEmailDomain from "./enforceEmailDomain";

// Registry of instantiated policies
export const Policies: Record<string, BasePolicy> = {
  [enforceEmailDomain.name]: enforceEmailDomain,
  // add more: [ipAllowlist.name]: ipAllowlist, ...
};

export function parseAndRun(policies: string[] | undefined, ctx: PolicyCtx): Promise<void> {
  if (!policies?.length) return Promise.resolve();

  return policies.reduce(async (prev, spec) => {
    await prev;
    const [name, argStr] = spec.split(":", 2);
    const p = Policies[name];
    if (!p) return; // silently ignore unknown policy
    const arg = argStr?.length ? argStr : undefined;
    return p.run(ctx, arg);
  }, Promise.resolve());
}
