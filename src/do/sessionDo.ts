export interface StoredSession {
    sub: string;
    email?: string;
    roles?: string[];
    claims?: Record<string, any>;
    createdAt: number;
    updatedAt: number;
}

export class SessionDO {
    private state: DurableObjectState;
    private cache?: StoredSession;

    constructor(state: DurableObjectState) {
        this.state = state;
    }

    async fetch(req: Request): Promise<Response> {
        const { op, session } = (await req.json().catch(() => ({}))) as { op?: string; session?: StoredSession };

        if (op === "put") {
            if (!session || !session.sub) {
                return json({ error: "invalid session: missing sub" }, { status: 400 });
            }
            const now = Date.now();
            this.cache = { ...session, createdAt: now, updatedAt: now } as StoredSession;
            await this.state.storage.put("session", this.cache);
            return json({ ok: true });
        }

        if (op === "get") {
            if (!this.cache) {
                this.cache =
                    (await this.state.storage.get<StoredSession>("session")) || undefined;
            }
            if (!this.cache) return json({ session: null });

            this.cache.updatedAt = Date.now();
            await this.state.storage.put("session", this.cache);
            return json({ session: this.cache });
        }

        if (op === "delete") {
            this.cache = undefined;
            await this.state.storage.delete("session");
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
