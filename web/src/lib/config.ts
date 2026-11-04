export interface AppConfig {
  apiOrigin: string;
  uploadOrigin: string;
}

let config: AppConfig | null = null;

export async function loadConfig(): Promise<AppConfig> {
  if (config) return config;
  const response = await fetch('/config.json');
  if (!response.ok) throw new Error('Failed to load config');
  config = (await response.json()) as AppConfig;
  return config;
}

export function getConfig(): AppConfig {
  if (!config) throw new Error('Config not loaded');
  return config;
}
