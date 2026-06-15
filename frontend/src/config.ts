/**
 * Server-injected application configuration.
 * FIXME(@florentc): Expose this through an API endpoint so we don't have to hard-code it.
 */

/** Server-injected configuration shape. */
export interface AppConfig {
  /** Whether Django DEBUG mode is active (indicates a testing environment). */
  debug: boolean;
  /** Whether to show the demo disclaimer (production deployment not yet stable). */
  showDemoDisclaimer: boolean;
  /** Whether this is a production deployment. */
  production: boolean;
  /** Git revision (commit SHA) of the running server. */
  revision: string;
}

declare global {
  interface Window {
    __CONFIG__?: AppConfig;
  }
}

const DEFAULT_CONFIG: AppConfig = {
  debug: true,
  showDemoDisclaimer: false,
  production: false,
  revision: "dev",
};

export function getConfig(): AppConfig {
  return window.__CONFIG__ ?? DEFAULT_CONFIG;
}
