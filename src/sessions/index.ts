import type { SessionStrategyCfg, ProjectConfig } from "../core/types";
import { signJwtHS256, verifyJwtHS256 } from "../utils/jwt";

export type Session = {
  sub: string;
  email?: string;
  roles?: string[];
  claims?: Record<string, any>;
};

export interface SessionStrategy {
  resolve(
    request: Request,
    env: any,
    cfg: ProjectConfig
  ): Promise<{ session: Session | null; accessJwt?: string }>;
  issue?(
    session: Session,
    env: any,
    cfg: ProjectConfig
  ): Promise<{ cookie?: string; accessJwt?: string }>;
  clear?(env: any, cfg: ProjectConfig): { cookie: string };
}

// Stateless cookie that IS the JWT
export class JwtSessionStrategy implements SessionStrategy {
  constructor(private cfg: SessionStrategyCfg & { kind: "jwt" }) {}

  async resolve(request: Request, env: any) {
    const token = getCookie(request, this.cfg.cookieName ?? "__Host-session");
    if (!token) return { session: null };

    try {
      const payload = await verifyJwtHS256(token, env[this.cfg.jwtSecretEnv]);
      return {
        session: {
          sub: payload.sub,
          email: payload.email,
          roles: payload.roles,
          claims: payload,
        },
      };
    } catch {
      return { session: null };
    }
  }

  async issue(session: Session, env: any) {
    const expMinutes = this.cfg.expMinutes ?? 15;
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signJwtHS256(
      {
        sub: session.sub,
        email: session.email,
        roles: session.roles,
        iat: now,
        exp: now + expMinutes * 60,
      },
      env[this.cfg.jwtSecretEnv]
    );
    return {
      cookie: `${this.cfg.cookieName ?? "__Host-session"}=${jwt}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    };
  }

  clear() {
    return {
      cookie: `${this.cfg.cookieName ?? "__Host-session"}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    };
  }
}

// Opaque sid cookie + DO state; mints short-lived access JWT
export class HandleSessionStrategy implements SessionStrategy {
  constructor(private cfg: SessionStrategyCfg & { kind: "handle" }) {}

  async resolve(request: Request, env: any, tenant: ProjectConfig) {
    const sid = getCookie(request, this.cfg.cookieName ?? "__Host-sid");
    if (!sid) return { session: null };

    const stub = env.SESSION_DO.get(env.SESSION_DO.idFromName(sid));
    const res = await stub.fetch("https://do/session", {
      method: "POST",
      body: JSON.stringify({ op: "get" }),
    });
    if (!res.ok) return { session: null };

    const data = await res.json();
    if (!data?.session) return { session: null };

    const now = Math.floor(Date.now() / 1000);
    const exp = now + 15 * 60;
    const accessJwt = await signJwtHS256(
      {
        sub: data.session.sub,
        email: data.session.email,
        roles: data.session.roles,
        iat: now,
        exp,
      },
      env["ACCESS_JWT_SECRET"]
    );
    return { session: data.session as Session, accessJwt };
  }

  async issue(session: Session, env: any) {
    const sid = crypto.randomUUID();
    const stub = env.SESSION_DO.get(env.SESSION_DO.idFromName(sid));
    const ok = await stub.fetch("https://do/session", {
      method: "POST",
      body: JSON.stringify({ op: "put", session }),
    });
    if (!ok) throw new Error("session create failed");

    const now = Math.floor(Date.now() / 1000);
    const exp = now + 15 * 60;
    const accessJwt = await signJwtHS256(
      {
        sub: session.sub,
        email: session.email,
        roles: session.roles,
        iat: now,
        exp,
      },
      env["ACCESS_JWT_SECRET"]
    );
    return {
      cookie: `${this.cfg.cookieName ?? "__Host-sid"}=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax`,
      accessJwt,
    };
  }

  clear() {
    return {
      cookie: `${this.cfg.cookieName ?? "__Host-sid"}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    };
  }
}

function getCookie(req: Request, name: string) {
  const h = req.headers.get("cookie");
  if (!h) return null;
  const m = h.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return m ? decodeURIComponent(m[1]) : null;
}