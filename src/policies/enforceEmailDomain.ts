import type { PolicyCtx } from "./types";
import { BasePolicy } from "./basePolicy";

class EnforceEmailDomain extends BasePolicy {
  constructor() {
    super("enforce-email-domain");
  }

  async handle({ session }: PolicyCtx, domain?: string) {
    if (!domain) this.deny(400, "Missing domain");
    if (!session?.email || !session.email.endsWith(`@${domain}`)) {
      this.deny(403, "Forbidden (email domain)");
    }
  }
}

export default new EnforceEmailDomain();
