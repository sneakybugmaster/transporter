export type VersionInfo = {
  version: string;
  commit: string;
  date: string;
  goVersion: string;
  platform: string;
};

export type Health = { status: string };

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`${path}: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export const api = {
  health: () => getJSON<Health>("/healthz"),
  version: () => getJSON<VersionInfo>("/api/v1/version"),
};
