import type { ProjectConfig } from "./core/types";

export const CONFIG: ProjectConfig = {
  projectName: "my-single-project",
  publicBaseUrl: "https://example.com",
  providers: [
    {
      id: "azure_b2c",
      enabled: true,
      label: "Sign in with Microsoft",
      clientId: "<YOUR_CLIENT_ID>",
      clientSecretEnv: "AZURE_B2C_CLIENT_SECRET",
      tenant: "contoso",
      b2cPolicy: "B2C_1_signupsignin",
      scope: "openid profile email offline_access"
    }
  ],
  defaultProvider: "azure_b2c",
  session: { kind: "handle", cookieName: "__Host-sid", doName: "SESSION_DO" },
  propagation: { headerName: "X-User", sigHeaderName: "X-User-Sig", hmacSecretEnv: "AUTH_HMAC_KEY" },
  routes: [
    { match: { path: "/public/**" }, auth: "none" },
    { match: { path: "/healthz" }, auth: "none" },
    { match: [{ path: "/api/**" }, { path: "/dashboard/**" }], auth: "required" },
    { match: { path: "/admin/**" }, auth: "required", rolesAll: ["admin"] }
  ],
  policies: {
    beforeAuth: [],
    afterAuth: ["enforce-email-domain:example.com"]
  }
};