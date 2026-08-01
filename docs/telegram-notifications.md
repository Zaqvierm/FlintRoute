# Telegram notifications and external SOCKS

Telegram delivery is an optional control-plane subsystem. Routing bootstrap,
health checks and rollback do not depend on it.

## Notifications

`PUT /api/v1/telegram/configure` accepts a bot token, chat ID, enabled flag and
event allowlist. When delivery is enabled, FlintRoute verifies both `getMe` and
`getChat` before storing the configuration. `POST /api/v1/telegram/test` sends a
real test message.

The secret file is a regular non-symlink file with mode `0600`; its directory is
created with mode `0700`. The token and chat ID are never returned through API,
events or status. Empty token/chat fields preserve existing values, so delivery
can be disabled without deleting its settings.

Runtime states are `not_configured`, `configured`, `verified`, `degraded` and
`failed`. Delivery uses a bounded queue, duplicate suppression, request
timeouts, minimum send interval and bounded exponential retry. Supported event
types are:

- `apply_succeeded`;
- `rollback`;
- `route_loss`;
- `recovery`;
- `auto_apply_blocked`;
- `storage_critical`.

## External SOCKS

FlintRoute does not ship or supervise a Telegram WebSocket transport. The route
type is therefore named `external_socks`: an operator supplies an existing
loopback SOCKS5 endpoint. FlintRoute owns only the Xray route that forwards to
that endpoint.

The setup API checks loopback addressing, TCP reachability, an unauthenticated
SOCKS5 handshake, remote-domain CONNECT, TLS and HTTP. A successful check does
not change routing. Activation is explicit and creates one normal ChangeSet for
the Xray mode, route and test-domain binding. The standard validate, apply,
PathVerified, confirm/rollback sequence remains authoritative.

Old persisted `tg_ws_proxy` route types and `tg-ws-proxy` tags are normalized to
`external_socks` and `external-socks` during config validation. No process is
killed, installed or restarted by this compatibility migration.

Hardware delivery and external transport availability still require a router
test with operator-provided credentials and endpoint.
