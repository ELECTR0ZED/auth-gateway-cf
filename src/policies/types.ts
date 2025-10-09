import type { ProjectConfig } from "../core/types";
import type { Session } from "../sessions";

export type PolicyCtx = {
  request: Request;
  url: URL;
  env: any;
  cfg: ProjectConfig;
  session?: Session;
};
