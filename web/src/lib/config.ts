import { z } from 'zod';

/**
 * The runtime config, `/config.json`, loaded before the app starts and never built in: one bundle for every
 * environment (ADR-0008). Each environment writes its own.
 *
 * - `apiOrigin`: where the API is, with its `/v1` prefix: `/v1` behind the dev server's proxy, or an absolute URL on
 *   the API's own origin (`http://localhost:8000/v1` in the compose stack, `https://api.<domain>/v1` in AWS).
 * - `uploadOrigin`: the object storage origin part uploads go to (the CSP's `connect-src` names it too).
 * - `signInOrigin`: the user pool's sign-in origin (Keycloak locally, managed login in AWS). Sign-out follows the
 *   API's logout URL only when it is on this origin (authn-authz 3.5).
 * - `ssoSignIn`: whether the sign-in page offers SSO (M6 turns it on).
 */
const httpOrigin = z
  .url({ protocol: /^https?$/ })
  .refine((value) => new URL(value).origin === value.replace(/\/$/, ''), 'an origin, without a path');

const configSchema = z.object({
  apiOrigin: z.union([z.literal('/v1'), z.url({ protocol: /^https?$/ })]),
  uploadOrigin: z.string(),
  signInOrigin: httpOrigin,
  ssoSignIn: z.boolean().default(false),
});

export type AppConfig = z.infer<typeof configSchema>;

let config: AppConfig | null = null;

/** Loads and checks `/config.json`. A malformed config fails the load, and the app shows its config error. */
export async function loadConfig(): Promise<AppConfig> {
  if (config) return config;
  const response = await fetch('/config.json');
  if (!response.ok) throw new Error('Failed to load config');
  config = configSchema.parse(await response.json());
  return config;
}

export function getConfig(): AppConfig {
  if (!config) throw new Error('Config not loaded');
  return config;
}

/** For tests: forget the loaded config, so the next `loadConfig` reads `/config.json` again. */
export function resetConfig(): void {
  config = null;
}

/** An API URL the browser navigates to (not an XHR): the sign-in start, for example. */
export function apiUrl(path: string): string {
  return `${getConfig().apiOrigin.replace(/\/$/, '')}${path}`;
}
