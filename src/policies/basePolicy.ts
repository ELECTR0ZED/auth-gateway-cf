import type { PolicyCtx } from "./types";

/**
 * Minimal base class for policies.
 * - Override `handle` with your core logic.
 * - Optionally use `before`/`after` hooks.
 * - Helpers included for common tasks (deny, parseList, getIp).
 */
export abstract class BasePolicy {
  readonly name: string;

  constructor(name: string) {
    this.name = name;
  }

  // Optional hooks
  async before(_ctx: PolicyCtx): Promise<void> {}
  async after(_ctx: PolicyCtx): Promise<void> {}

  // Implement in subclasses
  abstract handle(ctx: PolicyCtx, arg?: string): Promise<void>;

  // Entry point used by the registry
  async run(ctx: PolicyCtx, arg?: string): Promise<void> {
    await this.before(ctx);
    await this.handle(ctx, arg);
    await this.after(ctx);
  }

  // ---- Helpers ----
  protected deny(status = 403, message = "Forbidden"): never {
    throw new Response(message, { status });
  }

  protected parseList(arg?: string): string[] {
    if (!arg) return [];
    // Supports csv or pipe-separated: "a,b,c" or "a|b|c"
    return arg.split(/[|,]/).map(s => s.trim()).filter(Boolean);
  }

  protected getIp(ctx: PolicyCtx): string | null {
    return (
      ctx.request.headers.get("CF-Connecting-IP") ||
      ctx.request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      null
    );
  }
}
