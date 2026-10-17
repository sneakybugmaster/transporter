export const agentImage = "ghcr.io/sneakybugmaster/transporter:latest";

/** installCommands returns ready-to-paste enrollment commands. */
export function installCommands(url: string, secret: string) {
  return {
    linux: `sudo transporter up --coordinator ${url} --authkey ${secret}`,
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
