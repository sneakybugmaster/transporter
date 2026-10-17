const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** relativeTime formats a timestamp like "3 minutes ago" or "in 2 days". */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const diff = Math.round((new Date(iso).getTime() - now) / 1000);
  for (const [unit, secs] of units) {
    if (Math.abs(diff) >= secs || unit === "second") {
      return rtf.format(Math.round(diff / secs), unit);
    }
  }
  return "";
}

/** osLabel turns GOOS values into display names. */
export function osLabel(os: string): string {
  return { linux: "Linux", darwin: "macOS", windows: "Windows", freebsd: "FreeBSD" }[os] ?? (os || "unknown");
}
