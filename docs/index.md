# Transporter

Transporter is a self-hosted WireGuard mesh VPN. One public **coordinator** hands out addresses, keys and
access rules; every device runs the **agent**, which connects directly to its peers when the network allows
and relays through the coordinator when it doesn't. A web console manages the whole mesh.

| Binary | Role |
|---|---|
| `transporter-coordinator` | Control plane, STUN server, packet relay, admin API and the embedded web console. |
| `transporter` | Agent and CLI for every node (Linux, macOS, Windows; userspace mode anywhere). |

Both ship as static native binaries and as Docker images (`ghcr.io/sneakybugmaster/transporter-coordinator`,
`ghcr.io/sneakybugmaster/transporter`).

## Features

- **Mesh networking** over WireGuard, with NAT traversal (STUN, disco probing, simultaneous open) and a
  WebSocket relay that keeps traffic end-to-end encrypted.
- **Access control**: a HuJSON policy with tags, hosts, ports and tests, enforced on every node.
- **MagicDNS** (`<node>.mesh.internal`) and split DNS.
- **Subnet routers and exit nodes**.
- **Userspace mode**: no root, no TUN device; programs reach the mesh through a SOCKS5 proxy.
- **Web console**: setup wizard, nodes, enrollment, topology, routes, policy editor and simulator, DNS,
  audit log, settings.
- **Operations**: built-in HTTPS (Let's Encrypt), OIDC single sign-on, API tokens, node key expiry,
  Prometheus metrics, backup and restore, SQLite or Postgres.

## Where to go next

- [Getting started](getting-started.md): run a coordinator and enroll devices.
- [Configuration](configuration.md): every flag and environment variable.
- [Access control](policy.md): the policy language.
- [Operations](operations.md): TLS, SSO, API tokens, metrics, backups, Postgres, upgrades.
- [Security](security.md): threat model, hardening and known limitations.
