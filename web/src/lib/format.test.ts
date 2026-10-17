import { expect, test } from "vitest";

import { installCommands } from "./commands";
import { osLabel, relativeTime } from "./format";

test("relativeTime", () => {
  const now = Date.parse("2026-01-01T12:00:00Z");
  expect(relativeTime("2026-01-01T11:57:00Z", now)).toMatch(/3 minutes ago/);
  expect(relativeTime("2026-01-03T12:00:00Z", now)).toMatch(/in 2 days/);
  expect(relativeTime("2026-01-01T12:00:00Z", now)).toMatch(/now/);
});

test("osLabel", () => {
  expect(osLabel("darwin")).toBe("macOS");
  expect(osLabel("plan9")).toBe("plan9");
  expect(osLabel("")).toBe("unknown");
});

test("installCommands embed URL and key", () => {
  const c = installCommands("https://mesh.example.com", "trk_secret");
  expect(c.linux).toBe("sudo transporter service install --coordinator https://mesh.example.com --authkey trk_secret");
  expect(c.windows).toBe(".\\transporter.exe service install --coordinator https://mesh.example.com --authkey trk_secret");
  expect(c.docker).toContain("TRANSPORTER_COORDINATOR=https://mesh.example.com");
  expect(c.docker).toContain("TRANSPORTER_AUTHKEY=trk_secret");
  expect(c.docker).toContain("--device /dev/net/tun");
});
