# Getting started

## 1. Run the coordinator

The coordinator needs one public TCP port (HTTPS) and UDP 3478 (STUN). With a DNS name pointing at the host,
it can get its own certificate from Let's Encrypt:

```sh
docker run -d --name transporter-coordinator --restart unless-stopped \
  -p 443:443 -p 3478:3478/udp -v transporter-data:/data \
  -e TRANSPORTER_TLS_DOMAINS=mesh.example.com \
  ghcr.io/sneakybugmaster/transporter-coordinator:latest
docker logs transporter-coordinator 2>&1 | grep setupCode
```

To try it locally without TLS, publish `-p 8080:8080` instead and open <http://localhost:8080>. Behind an
existing reverse proxy, leave TLS off and proxy to port 8080 (WebSockets must be allowed for `/relay/v1` and
`/api/v1/events`, and HTTP/2 or long-lived streams for `/transporter.control.v1.*`).

Native binaries work the same way:

```sh
transporter-coordinator --data-dir /var/lib/transporter-coordinator --tls-domains mesh.example.com
```

## 2. Finish setup in the browser

Open the coordinator's URL. The setup wizard asks for the one-time **setup code** from the log (it proves you
run this coordinator), creates your admin account and asks for the URL devices will use to reach the
coordinator.

## 3. Enroll devices

On **Enroll device**, create an auth key; the page shows the command for each platform. Installing the agent
as a service enrolls and keeps it running across reboots:

```sh
# Linux (systemd) and macOS (launchd)
sudo transporter service install --coordinator https://mesh.example.com --authkey trk_...

# Windows (Administrator PowerShell; wintun.dll next to transporter.exe, as shipped in the zip)
.\transporter.exe service install --coordinator https://mesh.example.com --authkey trk_...
```

The auth key is only used to enroll and is never written into the service configuration. To run in the
foreground instead, use `transporter up` with the same flags.

In Docker, with a TUN interface:

```sh
docker run -d --name transporter --restart unless-stopped --cap-add NET_ADMIN --device /dev/net/tun \
  -v transporter-state:/var/lib/transporter \
  -e TRANSPORTER_COORDINATOR=https://mesh.example.com -e TRANSPORTER_AUTHKEY=trk_... \
  ghcr.io/sneakybugmaster/transporter:latest up
```

The device appears on the **Nodes** page as soon as it connects. On the device, `transporter status` lists
peers and how each is reached, and `transporter ping <peer>` measures round trips.

### Without root: userspace mode

`transporter up --userspace` runs WireGuard over an in-process network stack. It needs no root, TUN device or
capabilities. Programs reach the mesh through the agent's SOCKS5 proxy (default `127.0.0.1:1055`), which
resolves peer names:

```sh
transporter up --userspace --coordinator https://mesh.example.com --authkey trk_...
curl --socks5-hostname 127.0.0.1:1055 http://build-server:8080/
```

[`deploy/compose/agent-sidecar.yml`](https://github.com/sneakybugmaster/transporter/blob/main/deploy/compose/agent-sidecar.yml)
puts an unprivileged app container on the mesh this way. Keep the proxy on a loopback address: it does not
authenticate clients.

## How nodes connect

Each node learns its public address from the coordinator's STUN server and advertises it with its LAN
addresses. Peers probe those addresses with small encrypted "disco" packets and, through the coordinator, ask
each other to probe back at the same time, which opens most NATs. Until a direct path answers, and whenever
none can (for example both sides behind symmetric NATs), WireGuard packets are relayed through the coordinator
over a WebSocket; they stay end-to-end encrypted. `transporter status` shows each peer's path.

## Names, routes and exit nodes

- **MagicDNS.** Each node answers `<node>.mesh.internal` at `100.100.100.100` and points the system resolver
  there for that domain (systemd-resolved, `/etc/resolver` on macOS, NRPT on Windows; `--accept-dns=false`
  turns it off). The **DNS** page renames the domain and adds split DNS for other domains.
- **Subnet routers and exit nodes** (Linux, TUN mode):
  `transporter up --advertise-routes 10.1.0.0/24 --advertise-exit-node ...`. Approve on the **Routes** page or
  with the policy's `autoApprovers`. Other nodes opt in with `--accept-routes` and `--exit-node <name>`.
  In Docker, routers also need `--sysctl net.ipv4.ip_forward=1`.
