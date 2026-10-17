# Operations

## HTTPS

Node tokens, auth keys and admin sessions travel in requests, so expose the coordinator only over HTTPS.
Three ways:

- **Let's Encrypt, built in:** `--tls-domains mesh.example.com` (optionally `--acme-email`). Certificates are
  obtained with the TLS-ALPN-01 challenge on the TLS port (`--tls-listen`, default `:443`), so that port must be
  reachable as 443 from the internet. Certificates are cached in `<data-dir>/acme`.
- **Your own certificate:** `--tls-cert` and `--tls-key`. The files are re-read when the certificate changes,
  so a renewal by certbot or cert-manager needs no restart.
- **A reverse proxy** terminating TLS in front of `--listen`. It must pass WebSockets (`/relay/v1`,
  `/api/v1/events`) and long-lived streaming responses (`/transporter.control.v1.*`), and set
  `X-Forwarded-Proto`.

With built-in TLS the plain HTTP listener (`--listen`, `:8080`) keeps running for health checks and local
tools. Don't publish it: bind it to loopback (`--listen 127.0.0.1:8080`) or leave the port unmapped.

## Admin sign-in

### Single sign-on (OIDC)

Register the coordinator as a web application with your identity provider (Google, Microsoft Entra ID, Okta,
Keycloak, Authentik, ...), with redirect URL `https://mesh.example.com/api/v1/auth/oidc/callback`, then:

```sh
TRANSPORTER_OIDC_ISSUER=https://accounts.google.com
TRANSPORTER_OIDC_CLIENT_ID=1234.apps.googleusercontent.com
TRANSPORTER_OIDC_CLIENT_SECRET=...
TRANSPORTER_OIDC_ALLOWED=alice@example.com,@ops.example.com
TRANSPORTER_OIDC_NAME=Google
```

The login page shows a "Sign in with Google" button. The sign-in uses the authorization code flow with PKCE
and a nonce. Only verified email addresses listed in `--oidc-allowed` (exact addresses or `@domain`) get in;
the first sign-in creates an admin named after the email address, with no password. An existing password admin
with the same name is never taken over: rename it first. Password sign-in keeps working alongside SSO; finish
the setup wizard with a password admin first.

### API tokens

**Settings → API tokens** creates tokens (`tpa_...`) for scripts and automation. A token acts as the admin who
created it, is shown once, can have an expiry, and is revoked on the same page. Send it as a bearer token:

```sh
curl -H "Authorization: Bearer tpa_..." https://mesh.example.com/api/v1/nodes
curl -X PUT -H "Authorization: Bearer tpa_..." -H "Content-Type: application/json" \
  --data "{\"policy\": $(jq -Rs . < policy.hujson)}" https://mesh.example.com/api/v1/policy
```

Tokens cannot create other tokens or change passwords. Every change made with a token is audited as
`<admin> (API token <id>)`. The API is described in
[`api/openapi.yaml`](https://github.com/sneakybugmaster/transporter/blob/main/api/openapi.yaml).

## Node key expiry

**Settings → Node key expiry** makes node keys expire 30 to 365 days after enrollment (default: never). An
expired node is disconnected from the control plane and the relay, and its peers drop it. It rejoins with
`transporter up --authkey ...` using a fresh auth key, keeping its name and address. On the **Nodes** page you
can exempt a node (servers, routers) or expire its key immediately, for example for a lost laptop. Deleting a
node also closes its relay connection immediately.

## Monitoring

`--metrics-listen 127.0.0.1:9090` serves Prometheus metrics at `/metrics` on a separate listener, so they are
never exposed on the public port. Besides the Go runtime and process metrics:

| Metric | Type | Meaning |
|---|---|---|
| `transporter_nodes_online`, `transporter_nodes_offline` | gauge | enrolled nodes with/without a control stream |
| `transporter_control_streams` | gauge | open netmap streams |
| `transporter_registrations_total{result}` | counter | node registrations |
| `transporter_netmaps_sent_total`, `transporter_netmap_bytes_total` | counter | netmaps pushed to nodes |
| `transporter_snapshot_build_seconds` | histogram | time to compute the mesh view after a change |
| `transporter_relay_connections` | gauge | nodes connected to the relay |
| `transporter_relay_bytes_total` | counter | payload bytes relayed |
| `transporter_relay_dropped_{rate_limit,no_peer,slow_peer}_total` | counter | relay packets dropped, by reason |
| `transporter_stun_requests_total` | counter | STUN binding requests answered |
| `transporter_http_requests_total{area,code}` | counter | HTTP requests by area (api, control, relay, ui) |

A rising `relay_bytes` means many peers cannot connect directly; check firewalls for UDP 41641 and 3478.
`/healthz` on the main listener answers `200` while the server is up (the Docker image's health check uses
`transporter-coordinator --healthcheck`).

Logs are structured (`log/slog`) on stderr; `--log-level debug` adds per-node detail.

## Backup and restore

All coordinator state (nodes, keys, admins, policy, settings, audit log) is in the database. With SQLite:

```sh
transporter-coordinator backup /backups/transporter-$(date +%F).db   # safe while the server runs
docker exec transporter-coordinator transporter-coordinator backup /data/backup.db
```

To restore, stop the coordinator, then:

```sh
transporter-coordinator restore /backups/transporter-2026-10-01.db
```

`restore` checks the backup's integrity first and keeps the replaced database as
`coordinator.db.before-restore-<time>`. It refuses to run while a coordinator uses the data directory.
The data directory also holds ACME certificates (`acme/`), which are re-obtained if lost.

Nodes keep their keys, so after a restore they reconnect by themselves. Nodes enrolled after the backup was
taken must enroll again.

With Postgres, use the database's own tools (`pg_dump`, point-in-time recovery); `backup` refuses to run.

## Postgres

SQLite in the data directory suits most meshes, including the 1,000-node load test. To keep state in Postgres
(managed databases, existing backup tooling):

```sh
TRANSPORTER_DATABASE_URL=postgres://transporter:secret@db.internal/transporter?sslmode=require
```

The schema is created and migrated on start (CI tests against Postgres 17). Run only one coordinator against a database (this
is not enforced for Postgres); there is no high availability yet. Moving an existing SQLite mesh to Postgres is not automated.

## Upgrades

Replace the binary or image and restart. Database migrations run on start and are forward-only, so take a
backup first. Upgrade the coordinator before the agents. While the coordinator restarts, existing tunnels keep working; only enrollment, changes and
relayed traffic pause.

## Capacity

Measured with `test/load` (1,000 simulated nodes, all allowed to reach each other, on one development
machine):

| | SQLite | Postgres |
|---|---|---|
| every node has the full netmap after all registered | 4.2 s | 5.9 s |
| one endpoint change reaches all nodes | ~2.5 s | ~3 s |

Netmaps are sent in full (about 120 KB per node at 1,000 fully meshed nodes), so each change costs roughly
`nodes × netmap size` of bandwidth. An access policy that limits who sees whom shrinks both.
