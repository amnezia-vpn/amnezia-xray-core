# External routing by authenticated VLESS user

This example keeps classification inside Xray and delegates the selected
egress path to the operating system:

```text
unknown VLESS UUID
  -> /run/xray/auth-notifications.sock
  -> auth daemon
  -> /run/xray/control.sock (gRPC RoutingService.ReplaceRuleSet)
  -> /run/xray/control.sock (gRPC HandlerService.AlterInbound/AddUser)
  -> new VLESS connection
  -> authenticated (inbound tag, user ID) + logical destination
  -> Xray routing rule
  -> outbound class
  -> optional outbound socket mark
  -> Linux policy routing
```

The notification and control sockets are separate. The first carries
length-prefixed `UnknownUserAttempt` protobuf frames; the second carries gRPC.
Xray listens on both sockets and the auth daemon connects to both.

## Authentication flow

The example server starts with no VLESS users. When an unknown UUID connects,
the VLESS inbound writes:

```text
uint32 big-endian protobuf length
xray.proxy.vless.inbound.UnknownUserAttempt
```

The message contains the remote endpoint, attempted UUID, and timestamp. The
auth daemon resolves that credential in its own backend and calls:

```text
HandlerService.AlterInbound(
  tag = "vless-in",
  operation = AddUserOperation(
    user.email = canonical opaque user ID,
    user.account = VLESS account
  )
)
```

The connection that produced the notification has already failed
authentication. `AddUser` cannot revive it; the client must establish a new
physical VLESS connection. Client retry can be automatic, but the server-side
contract remains reject-then-add-then-reconnect.

Use a non-empty canonical opaque database ID in `user.email`; do not put the
bearer UUID there. Routing identity is the pair `(inboundTag, user)`, so every
per-user rule in this example contains both fields.

This fork deliberately ignores UUID bytes 6 and 7 during VLESS lookup and
exposes those client-controlled bytes as `vlessRoute`. An auth daemon must
normalize those bytes before backend lookup. `vlessRoute` is not trusted user
identity.

`AddUser` is an in-memory, non-idempotent operation. The daemon must:

- singleflight provisioning by normalized credential;
- prevent two user IDs from claiming the same normalized UUID;
- reconcile ambiguous RPC results with `GetInboundUsers`;
- replay users and routing desired state after Xray restarts.

## Routing control plane

Rules are evaluated in order and conditions inside one rule are combined with
AND. The first example rule means:

```text
inbound vless-in
AND user client-42
AND configured Russian-service domain
-> ru-system
```

The user fallback must remain after the more specific Russian-service rule.
The final inbound-wide rule sends any VLESS user without an installed policy
to `deny`. `deny` is also the first outbound, so a malformed or incomplete
replacement remains fail-closed.

Infrastructure can keep these rules in the static config or manage the full
desired rule set through `RoutingService` on the same Commander Unix socket.
For live updates use:

1. `GetRuleSet`
2. build a complete ordered desired state
3. `ReplaceRuleSet(expected_version, config)`

`GetRuleSet` returns only the version unless `include_config` is true. A
controller that owns desired state should use the version-only form. If the
controller must read a large live config, its gRPC client also needs a matching
receive limit (for grpc-go, `grpc.MaxCallRecvMsgSize`).

The version contains an Xray instance ID and generation. Replacement is
compare-and-swap: a stale controller receives a conflict, and an invalid
candidate leaves the live rules unchanged. The legacy per-rule mutation RPCs
remain for compatibility but are implemented through the same copy-on-write
state.

The example raises Commander's receive/send limits to 16 MiB for full
rule-set replacement. Set explicit limits appropriate for the maximum desired
state; leaving them at zero keeps the gRPC defaults.

Treat a successful `GetRuleSet` as the rollout capability check. An older core
returns gRPC `UNIMPLEMENTED` for the new RPC and must not be provisioned as if
it supported atomic policy updates.

For a new dynamic user, install its routing desired state before calling
`AddUser`. For revocation, first replace the user's policy with an explicit
`deny` tombstone and then remove the user. Keep the tombstone until all
pre-existing connections have expired: removing a validator entry does not
terminate an already authenticated mux connection.

If infrastructure creates per-user outbound classes dynamically, add the
outbound through `HandlerService.AddOutbound` before publishing rules that
reference it. Remove it only after the deny/remove/drain sequence.

## Mux behavior

Mux and connection reuse are unchanged. A single authenticated physical VLESS
connection can carry several logical streams. Every inner stream retains the
authenticated user and its own destination, so Xray can route two simultaneous
destinations to different outbound classes without splitting the inbound mux
connection.

The regression scenario proves the complete path:

```bash
go test ./testing/scenarios \
  -run '^TestVlessMuxUserDestinationRouting$' \
  -count=1
```

It starts Xray with an empty VLESS user set, consumes the notification socket,
updates the rule snapshot and calls the real proxyman `AddUser` RPC over a
second Unix socket. It verifies that the unknown connection fails, the retry
succeeds, two concurrent logical mux streams reach different backends, and
only one new post-auth physical VLESS connection is created.

Unknown-user attempts are not retained while no notification client is
connected. Start the auth daemon and confirm both Unix-socket connections
before exposing the VLESS listener, and keep client reconnect/retry enabled.
This avoids storing bearer credentials in an unbounded offline queue.

## System routing

`ru-system` sets mark `100`. Xray selects the outbound class and applies the
mark to the outbound socket; Linux interprets it:

```bash
sudo ip route add default via <RU_GATEWAY> dev <RU_INTERFACE> table 100
sudo ip rule add priority 100 fwmark 100 lookup 100

sudo ip -6 route add default via <RU_IPV6_GATEWAY> dev <RU_INTERFACE> table 100
sudo ip -6 rule add priority 100 fwmark 100 lookup 100
```

Applying `SO_MARK` normally requires `CAP_NET_ADMIN`; supported kernels may
also permit `CAP_NET_RAW`. Socket options keep Xray's existing best-effort
behavior: an application error is logged and the connection may use the
default route. Deployment checks must verify the effective mark and Linux
policy-routing rules before serving traffic.

## Example configuration

Validate the client sample on any supported host and the server sample on
Linux. The server sample intentionally relies on Linux `SO_MARK`:

```bash
xray run -test -config examples/external-routing/client.json
# Linux:
xray run -test -config examples/external-routing/server.json
```

The server paths assume a root-created `/run/xray` directory with mode `0700`
and ownership assigned to the Xray service account. Both sockets use mode
`0600`. Commander has no independent
authentication layer, so filesystem ownership and permissions are the
control-plane security boundary; do not use an abstract or network-exposed
socket for this API.

The sample domain list is illustrative. Infrastructure is responsible for
maintaining production domain and CIDR data. If Xray receives only an IP
destination, a domain rule can match only when sniffing recovers a hostname;
use maintained IP rules for traffic that must be classified without one.
