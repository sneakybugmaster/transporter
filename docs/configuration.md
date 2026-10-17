# Configuration

Every flag can also be set with the environment variable shown, which is the usual way in Docker.

## Coordinator (`transporter-coordinator`)

| Flag | Environment variable | Default |
|---|---|---|
| `--listen` | `TRANSPORTER_LISTEN` | `:8080` (plain HTTP) |
| `--data-dir` | `TRANSPORTER_DATA_DIR` | `./data` (`/data` in Docker) |
| `--database-url` | `TRANSPORTER_DATABASE_URL` | unset: SQLite in the data dir; or `postgres://user:pass@host/db` |
| `--network-prefix` | `TRANSPORTER_NETWORK_PREFIX` | `100.64.0.0/10` |
| `--tls-domains` | `TRANSPORTER_TLS_DOMAINS` | unset; comma-separated names to get Let's Encrypt certificates for |
| `--acme-email` | `TRANSPORTER_ACME_EMAIL` | unset; contact address for Let's Encrypt |
| `--tls-cert`, `--tls-key` | `TRANSPORTER_TLS_CERT`, `TRANSPORTER_TLS_KEY` | unset; PEM files, reloaded when the certificate changes |
| `--tls-listen` | `TRANSPORTER_TLS_LISTEN` | `:443` (when TLS is enabled) |
| `--stun-listen` | `TRANSPORTER_STUN_LISTEN` | `:3478` (UDP; empty disables) |
| `--relay` | `TRANSPORTER_RELAY` | `true` |
| `--relay-rate` | `TRANSPORTER_RELAY_RATE` | `4194304` bytes/s per node (0 = unlimited) |
| `--metrics-listen` | `TRANSPORTER_METRICS_LISTEN` | unset; e.g. `127.0.0.1:9090` serves `/metrics` |
| `--oidc-issuer` | `TRANSPORTER_OIDC_ISSUER` | unset; enables single sign-on |
| `--oidc-client-id` | `TRANSPORTER_OIDC_CLIENT_ID` | |
| (no flag) | `TRANSPORTER_OIDC_CLIENT_SECRET` | kept out of the process list on purpose |
| `--oidc-allowed` | `TRANSPORTER_OIDC_ALLOWED` | emails or `@domain`s allowed to sign in; empty allows nobody |
| `--oidc-name` | `TRANSPORTER_OIDC_NAME` | `single sign-on` (label of the sign-in button) |
| `--oidc-redirect-url` | `TRANSPORTER_OIDC_REDIRECT_URL` | `<public URL>/api/v1/auth/oidc/callback` |
| `--bootstrap-authkey` | `TRANSPORTER_BOOTSTRAP_AUTHKEY` | unset; ensures a reusable key with this value exists |
| `--setup-code` | `TRANSPORTER_SETUP_CODE` | random, printed in the log while setup is pending |
| `--log-level` | `TRANSPORTER_LOG_LEVEL` | `info` |

Runtime settings (public URL, key expiry, policy, DNS) live in the database and are changed in the console or
through the [admin API](https://github.com/sneakybugmaster/transporter/blob/main/api/openapi.yaml).

### Subcommands

| Command | Purpose |
|---|---|
| `serve` (default) | Run the coordinator. |
| `authkey create\|list\|revoke` | Manage auth keys. |
| `nodes list\|delete\|tag\|approve-routes` | Manage nodes. |
| `policy get\|set` | Read or replace the access policy. |
| `backup <file>` | Write a consistent copy of the SQLite database, also while the server runs. |
| `restore <file>` | Replace the database with a backup; the server must be stopped. |

All take `--data-dir` and `--database-url`. Admin commands can run next to the server; nodes pick up their
changes within 30 seconds.

## Agent (`transporter up`)

| Flag | Environment variable | Default |
|---|---|---|
| `--coordinator` | `TRANSPORTER_COORDINATOR` | required |
| `--authkey` | `TRANSPORTER_AUTHKEY` | needed only to enroll (and after the node key expires) |
| `--hostname` | `TRANSPORTER_HOSTNAME` | system hostname |
| `--state-dir` | `TRANSPORTER_STATE_DIR` | `/var/lib/transporter`; macOS `/Library/Application Support/Transporter`; Windows `%ProgramData%\Transporter` |
| `--listen-port` | | `41641` (UDP) |
| `--interface` | | `transporter0` (macOS always uses the next free `utunN`) |
| `--advertise-endpoints` | `TRANSPORTER_ADVERTISE_ENDPOINTS` | extra `ip:port` endpoints, comma-separated |
| `--userspace` | `TRANSPORTER_USERSPACE` | `false`; in-process network stack instead of a TUN interface |
| `--socks5` | `TRANSPORTER_SOCKS5` | `127.0.0.1:1055` with `--userspace`, otherwise off; `off` disables |
| `--advertise-routes` | `TRANSPORTER_ADVERTISE_ROUTES` | subnets (CIDR) to offer; Linux TUN mode, needs approval |
| `--advertise-exit-node` | `TRANSPORTER_ADVERTISE_EXIT_NODE` | `false`; offer internet access through this node |
| `--accept-routes` | `TRANSPORTER_ACCEPT_ROUTES` | `false`; use other nodes' approved subnet routes |
| `--exit-node` | `TRANSPORTER_EXIT_NODE` | peer name or mesh IP to send internet traffic through |
| `--accept-dns` | `TRANSPORTER_ACCEPT_DNS` | `true`; point the system resolver at MagicDNS |
| `--log-level` | `TRANSPORTER_LOG_LEVEL` | `info` |

Other agent commands: `down`, `status [--json]`, `ping <peer>`, `service install|uninstall`, `version`.
