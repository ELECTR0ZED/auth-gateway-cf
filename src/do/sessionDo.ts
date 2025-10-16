// do/sessionDo.ts
import { DurableObject } from "cloudflare:workers";
import type { StoredSession } from "../core/types";

type DOStored = StoredSession & {
    // Expiry metadata
    expiresAt: number;     // sliding (idle) expiry cutoff (ms epoch)
    absoluteAt: number;    // hard expiry cutoff (ms epoch)
    idleMs: number;        // configured sliding window in ms (persisted)
};

export class SessionDO extends DurableObject {
    private cache?: DOStored;

    constructor(ctx: DurableObjectState, env: Env) {
        super(ctx, env);
        // Ensure we hydrate/clean before serving requests after cold start.
        this.ctx.blockConcurrencyWhile(async () => {
            const s = await this.ctx.storage.get<DOStored>("session");
            if (s && this.isExpired(s)) {
                await this.deleteSession();
            } else if (s) {
                this.cache = s;
                await this.scheduleAlarm(s);
            }
        });
    }

    async fetch(req: Request): Promise<Response> {
        if (req.method !== "POST")
            return new Response("method not allowed", { status: 405 });

        const ct = req.headers.get("content-type") || "";
        if (!ct.includes("application/json")) {
            return json({ error: "bad content-type" }, { status: 400 });
        }

        const { op, session, idleTtlSec, absoluteTtlSec } = (await req.json().catch(() => ({}))) as {
            op?: string;
            session?: StoredSession;
            idleTtlSec?: number;
            absoluteTtlSec?: number;
        };

        if (op === "put") {
            if (!session?.sub)
                return json({ error: "invalid session: missing sub" }, { status: 400 });

            const now = Date.now();
            const idleMs = (idleTtlSec ?? 14 * 24 * 60 * 60) * 1000;      // default 14d
            const absMs = (absoluteTtlSec ?? 30 * 24 * 60 * 60) * 1000;   // default 30d

            const stored: DOStored = {
                ...session,
                createdAt: now,
                updatedAt: now,
                idleMs,
                expiresAt: now + idleMs,
                absoluteAt: now + absMs,
            };

            this.cache = stored;
            await this.ctx.storage.put("session", stored);
            await this.ctx.storage.setAlarm(new Date(Math.min(stored.expiresAt, stored.absoluteAt)));
            return json({ ok: true });
        }

        if (op === "get") {
            if (!this.cache) {
                this.cache = (await this.ctx.storage.get<DOStored>("session")) || undefined;
            }
            if (!this.cache)
                return json({ session: null });

            if (this.isExpired(this.cache)) {
                await this.deleteSession();
                return json({ session: null });
            }

            // Slide idle expiry without exceeding absolute expiry
            const now = Date.now();
            this.cache.updatedAt = now;
            this.cache.expiresAt = Math.min(now + this.cache.idleMs, this.cache.absoluteAt);

            await this.ctx.storage.put("session", this.cache);
            await this.ctx.storage.setAlarm(new Date(Math.min(this.cache.expiresAt, this.cache.absoluteAt)));

            const { expiresAt: _e1, absoluteAt: _e2, idleMs: _e3, ...publicSession } = this.cache;
            return json({ session: publicSession });
        }

        if (op === "delete") {
            await this.deleteSession();
            return json({ ok: true });
        }

        return new Response("bad op", { status: 400 });
    }

    // Alarm is called when we scheduled it.
    async alarm(): Promise<void> {
        const s = (await this.ctx.storage.get<DOStored>("session")) || undefined;
        if (!s)
            return;

        if (this.isExpired(s)) {
            await this.deleteSession();
            return;
        }

        // Not expired yet (timer resolution / slight skew) → re-arm.
        await this.ctx.storage.setAlarm(new Date(Math.min(s.expiresAt, s.absoluteAt)));
    }

    private isExpired(s: DOStored): boolean {
        const now = Date.now();
        return now >= s.expiresAt || now >= s.absoluteAt;
    }

    private async scheduleAlarm(s?: DOStored) {
        if (!s) {
            await this.ctx.storage.deleteAlarm?.();
            return;
        }
        await this.ctx.storage.setAlarm(new Date(Math.min(s.expiresAt, s.absoluteAt)));
    }

    private async deleteSession() {
        this.cache = undefined;
        await this.ctx.storage.delete("session");
        await this.ctx.storage.deleteAlarm?.();
    }
}

function json(obj: any, init: ResponseInit = {}): Response {
    return new Response(JSON.stringify(obj), {
        ...init,
        headers: { "content-type": "application/json" },
    });
}
