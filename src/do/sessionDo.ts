import { DurableObject } from "cloudflare:workers"
export interface StoredSession {
    sub: string;
    email?: string;
    claims?: Record<string, any>;
    createdAt: number;
    updatedAt: number;
}

export class SessionDO extends DurableObject {
    private cache?: StoredSession;

    constructor(ctx: DurableObjectState, env: Env) {
        super(ctx, env)
    }

    async fetch(req: Request): Promise<Response> {
        const { op, session } = (await req.json().catch(() => ({}))) as { op?: string; session?: StoredSession };

        if (op === "put") {
            if (!session || !session.sub) {
                return json({ error: "invalid session: missing sub" }, { status: 400 });
            }
            const now = Date.now();
            this.cache = { ...session, createdAt: now, updatedAt: now } as StoredSession;
            await this.ctx.storage.put("session", this.cache);
            return json({ ok: true });
        }

        if (op === "get") {
            if (!this.cache) {
                this.cache =
                    (await this.ctx.storage.get<StoredSession>("session")) || undefined;
            }
            if (!this.cache) return json({ session: null });

            this.cache.updatedAt = Date.now();
            await this.ctx.storage.put("session", this.cache);
            return json({ session: this.cache });
        }

        if (op === "delete") {
            this.cache = undefined;
            await this.ctx.storage.delete("session");
            return json({ ok: true });
        }

        return new Response("bad op", { status: 400 });
    }
}

function json(obj: any, init: ResponseInit = {}): Response {
    return new Response(JSON.stringify(obj), {
        ...init,
        headers: { "content-type": "application/json" },
    });
}
