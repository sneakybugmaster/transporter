export const agentImage = "ghcr.io/sneakybugmaster/transporter:latest";

export type Platform = "linux" | "macos" | "windows" | "docker";

export const platforms: { id: Platform; label: string; note: string }[] = [
  { id: "linux", label: "Linux", note: "Enrolls and installs a systemd service. Put the binary in /usr/local/bin first." },
  { id: "macos", label: "macOS", note: "Enrolls and installs a launch daemon." },
  { id: "windows", label: "Windows", note: "In an Administrator PowerShell, from the folder with transporter.exe and wintun.dll." },
  { id: "docker", label: "Docker", note: "Needs NET_ADMIN and /dev/net/tun; or add --userspace for an unprivileged container." },
];

/** installCommands returns ready-to-paste enrollment commands per platform. */
export function installCommands(url: string, secret: string): Record<Platform, string> {
  return {
    linux: `sudo transporter service install --coordinator ${url} --authkey ${secret}`,
    macos: `sudo transporter service install --coordinator ${url} --authkey ${secret}`,
    windows: `.\\transporter.exe service install --coordinator ${url} --authkey ${secret}`,
    docker: [
      "docker run -d --name transporter --restart unless-stopped \\",
      "  --cap-add NET_ADMIN --device /dev/net/tun \\",
      "  -v transporter-state:/var/lib/transporter \\",
      `  -e TRANSPORTER_COORDINATOR=${url} \\`,
      `  -e TRANSPORTER_AUTHKEY=${secret} \\`,
      `  ${agentImage} up`,
    ].join("\n"),
  };
}
