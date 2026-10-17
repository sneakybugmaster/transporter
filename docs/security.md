# Security

This page is the security review done for v1.0: what Transporter protects, how, and where its limits are.
To report a vulnerability, use GitHub's
[private vulnerability reporting](https://github.com/sneakybugmaster/transporter/security/advisories/new)
rather than a public issue.

## What is trusted

| Party | Trust |
|---|---|
| **Coordinator** | Fully trusted for membership: it decides which keys are peers, which addresses they have and which rules apply. It never sees traffic contents. |
| **Nodes** | Trusted to hold their own WireGuard private key. A node can only send traffic its peers' filters accept. |
| **Network** (including the relay path) | Untrusted. It can drop, delay and replay packets but not read or forge them. |
| **Admins** | Fully trusted: they control membership and policy. |

## Protections

**Traffic.** All mesh traffic is WireGuard (Noise IK, ChaCha20-Poly1305), end to end between nodes; the relay
forwards ciphertext. Disco messages (path probing) are sealed with XChaCha20-Poly1305 under a key derived from
both nodes' WireGuard keys, and carry a counter checked against a 1,024-message sliding window, so captured
probes cannot be replayed.

**Access control** is enforced twice: the coordinator only tells a node about peers it may talk to, and every
receiving node runs a stateful packet filter built from the policy. Routed traffic passes the router's filter.

**Node authentication.** Nodes enroll with an auth key (256-bit random, stored as a SHA-256 hash, optionally
single-use, expiring and tagged), and then authenticate with a per-node token (256-bit, hashed at rest) that is
rotated on every enrollment. The relay accepts only the token of the node whose key it relays for. Deleted and
expired nodes are disconnected from the control plane and relay immediately. Optional node key expiry forces
periodic re-enrollment.

**Admin authentication.** Passwords are hashed with argon2id. Sessions are server-side, referenced by an
HttpOnly, SameSite=Strict cookie (Secure over HTTPS). State-changing requests must be JSON and pass an Origin
check, which defeats cross-site request forgery. Login and setup are rate limited per client address. The
first-run wizard requires a one-time code from the server log. OIDC uses the authorization code flow with PKCE,
a nonce and a browser-bound state cookie, accepts only verified, allow-listed email addresses, and never links
an SSO identity to an existing password admin. API tokens are hashed at rest, can expire, and cannot mint
tokens or change passwords. Every admin change is written to the audit log.

**Transport.** Built-in HTTPS (TLS 1.2+, Let's Encrypt or your certificate) or a TLS-terminating proxy.

**Agent host.** The local API is a Unix socket readable only by root (on Windows, protected by the state
directory's ACL). The systemd unit runs with `ProtectSystem`, `ProtectHome` and only `CAP_NET_ADMIN` and
`CAP_NET_RAW`. Userspace mode needs no privileges at all.

**Supply chain and code.** Release archives and images are built by GoReleaser in GitHub Actions; the checksum
file and images are signed with keyless cosign (Sigstore) and every archive ships an SPDX SBOM. CI runs
`govulncheck`, `golangci-lint` (including gosec), the race detector, and fuzz tests for every parser that reads
network input: STUN, disco, relay framing, the packet filter, DNS, SOCKS5 and the policy language.
Dependabot keeps dependencies current.

### Verifying a release

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/sneakybugmaster/transporter/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --ignore-missing -c checksums.txt

cosign verify ghcr.io/sneakybugmaster/transporter-coordinator:v1.0.0 \
  --certificate-identity-regexp '^https://github.com/sneakybugmaster/transporter/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Known limitations

- **A compromised coordinator can add peers.** It cannot decrypt existing traffic, but it can introduce a node
  of its own and allow it through every filter. Signed node keys ("tailnet lock") are future work.
- **Agents trust the coordinator through Web PKI only.** There is no pinning of the coordinator's identity, so a
  mis-issued certificate for its domain would allow impersonation. Use a domain whose certificate issuance you
  control (CAA records).
- **The plain HTTP listener stays on** next to built-in HTTPS. Keep it unpublished or on loopback.
- **The SOCKS5 proxy of userspace mode does not authenticate clients.** Keep it on a loopback address.
- **Auth key enrollment is not rate limited** beyond the cost of guessing a 256-bit secret.
- **Single coordinator.** If it is down, existing direct tunnels keep working but relayed traffic, enrollment
  and changes stop. There is no high availability.
- **IPv4 only** inside the mesh and for peer-to-peer paths.
- Exit nodes can be used only from Linux in TUN mode or from userspace mode; subnet routers and exit nodes
  must be Linux in TUN mode.
