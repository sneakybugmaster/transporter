# Access control

By default every node may reach every other node. **Access control** in the console (or
`transporter-coordinator policy get|set`, or `PUT /api/v1/policy`) holds a policy written in HuJSON: JSON with
comments and trailing commas.

```jsonc
{
  "hosts": {"office": "10.1.0.0/24"},
  "acls": [
    // Developers may SSH to servers and reach the office LAN on any port.
    {"action": "accept", "src": ["tag:dev"], "dst": ["tag:server:22", "office:*"]},
    {"action": "accept", "src": ["tag:server"], "dst": ["tag:db:5432"], "proto": "tcp"},
  ],
  "autoApprovers": {"routes": {"10.1.0.0/24": ["tag:router"]}, "exitNode": ["tag:exit"]},
  "tests": [{"src": "tag:dev", "accept": ["tag:server:22"], "deny": ["tag:db:5432"]}],
}
```

## Selectors

Sources and destinations are selectors:

| Selector | Matches |
|---|---|
| `*` | anything |
| `tag:<name>` | nodes with that tag |
| `<node name>` | one node |
| `<host alias>` | a prefix named in `hosts` |
| `10.1.2.3`, `10.1.0.0/24` | an address or prefix: mesh addresses, or networks behind subnet routers |

Destinations add ports after a colon: `*`, a port (`22`), a range (`8000-8999`) or a comma-separated list
(`tag:web:80,443`). `proto` limits a rule to `tcp`, `udp` or `icmp`.

## How rules are enforced

- Anything no rule accepts is dropped **by the receiving node's packet filter**. Replies to connections a node
  opened always get through (the filter is stateful).
- A node only learns about peers it may talk to in either direction, so hidden peers are not even in its
  WireGuard configuration.
- Routed traffic is subject to the same rules: `"dst": ["10.1.0.0/24:443"]` allows HTTPS to that subnet
  through its router.

## Tags

Nodes get tags from the auth key they enrolled with, or from an admin on the **Nodes** page
(`transporter-coordinator nodes tag <node> tag:a tag:b`). Tags are lowercase: `tag:` followed by letters,
digits and dashes.

## Auto-approvers

`autoApprovers.routes` maps a prefix to the selectors whose nodes may advertise it (or any prefix inside it)
without an admin approving. `autoApprovers.exitNode` does the same for exit nodes.

## Tests

`tests` are checked against the current nodes whenever the policy is saved; a failing test rejects the change.
Each test names a source and destinations that must be accepted or denied. The simulator on the same page
checks one connection against the saved policy or your unsaved draft.
