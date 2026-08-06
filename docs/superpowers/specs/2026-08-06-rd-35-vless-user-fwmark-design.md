# RD-35: Per-user VLESS fwmark for Freedom

## Status

Approved design for the first pull request in the RD-35/RD-37 stack, amended after final review to describe the implemented conservative fail-closed contract.

- RD-35 is based on `frog/external-user-routing`.
- RD-37 will be developed in a second branch based on the completed RD-35 branch.
- RD-36 profiling is outside this stack.

## Problem

WireGuard and AWG users have an internal address that infrastructure can use for abuse investigation and policy routing. VLESS users currently have no equivalent value on their outgoing sockets. Xray supports a static `sockopt.mark`, but it is shared by an outbound and cannot identify the authenticated VLESS user.

RD-35 adds a backend-assigned `fwmark` to each VLESS user. When that user reaches a supported direct `freedom` transport, the physical socket created for the logical flow receives that value through Linux `SO_MARK` before the connection is established. Paths whose shared or pooled socket lifecycle cannot safely carry a call-local mark fail closed.

## Goals

- Accept a backend-assigned `fwmark` on VLESS users in static JSON configuration.
- Accept and return the same field through the existing gRPC user-management API.
- Apply the user mark to every supported direct TCP or UDP socket created by `freedom` for that user.
- Preserve authenticated VLESS metadata across inbound mux substreams so each logical stream reaches outbound selection with the same user identity and mark.
- Keep socket settings isolated between concurrent users.
- Fail closed when a non-zero user mark cannot be guaranteed.
- Support the full unsigned 32-bit mark range required by the backend.

## Non-goals

- Xray does not allocate, persist, or globally coordinate fwmarks.
- Xray does not enforce fwmark uniqueness. The backend guarantees uniqueness within the worker's allocation domain.
- RD-35 does not mark inbound VLESS packets or promise marks on reply packets.
- RD-35 does not add per-user outbounds, routing rules, or connection pools.
- RD-35 does not add mark-aware outbound mux/XUDP worker partitioning or a mark-aware lifecycle for pooled transport clients.
- RD-35 does not implement the RD-37 one-UUID/one-IP policy.
- RD-35 does not profile or optimize Xray performance; that remains RD-36.

## External contract

### User field

Add an unsigned field to the shared user message:

```proto
message User {
  uint32 level = 1;
  string email = 2;
  xray.common.serial.TypedMessage account = 3;
  uint32 fwmark = 4;
}
```

`protocol.MemoryUser` carries the same `uint32 Fwmark` value. `User.ToMemoryUser` and `ToProtoUser` preserve it in both directions.

Although `User` is shared by several protocols, RD-35 validates and consumes the field only for VLESS inbound users. Other protocols keep their current behavior.

### Static JSON

The existing VLESS parser unmarshals each raw user object into both `protocol.User` and the VLESS account. Consequently, the following needs no separate VLESS JSON structure:

```json
{
  "id": "00000000-0000-0000-0000-000000000001",
  "email": "example",
  "fwmark": 1000000000
}
```

### gRPC

The repository has no RPC literally named `AddInboundUser`. Dynamic user addition uses the existing API:

```text
HandlerService.AlterInbound
  operation = AddUserOperation
    user = protocol.User { ... fwmark ... }
```

Adding `fwmark` to `protocol.User` therefore extends `AlterInbound + AddUserOperation` without adding another RPC. `GetInboundUsers` returns the value through `ToProtoUser`.

Older clients omit the additive field and retain `fwmark = 0`. Backend clients must regenerate their protobuf bindings before they can send it.

### Value rules

The accepted values are:

- `0`: per-user marking is disabled.
- `1_000_000_000` through `4_294_967_295`, inclusive: valid backend-assigned fwmark.

Values from `1` through `999_999_999` are invalid. JSON values outside the `uint32` range fail during decoding.

The VLESS validator checks the value before modifying its email or UUID indexes. Invalid static users prevent inbound initialization. Invalid dynamic users cause the `AlterInbound` operation to fail without adding the user.

## Unsigned socket marks

Change the transport `SocketConfig.mark` protobuf and the corresponding JSON/config and runtime fields from `int32` to `uint32`. Linux fwmarks are unsigned 32-bit values, and the backend contract uses the complete range.

The same type change is propagated to internal mark holders that receive `SocketConfig.Mark`, including `session.Sockopt`. The syscall boundary preserves all 32 bits when passing the mark to `setsockopt`.

This protobuf change retains the varint wire type for existing non-negative values. Existing positive marks keep the same meaning. Negative static marks were not meaningful fwmarks and become invalid configuration. Go consumers that assign an `int32` variable directly to `SocketConfig.Mark` must update to `uint32`.

## Runtime data flow

```text
backend-generated fwmark
  -> protocol.User.Fwmark
  -> protocol.MemoryUser.Fwmark
  -> VLESS validator
  -> authenticated session.Inbound.User
  -> Freedom outbound-context preflight before mux/XUDP selection
  -> immutable call-scoped outbound socket mark
  -> outbound mux or XUDP selected: typed fail-closed rejection
  -> gRPC transport, Hysteria transport, or SplitHTTP/xhttp selected: typed fail-closed rejection
  -> supported direct transport: per-call cloned MemoryStreamConfig and SocketConfig
  -> direct transport dialer -> Linux SO_MARK before connect
```

### Selecting the mark

Freedom is the only outbound implementation that opts into the user policy. Its optional outbound-context preflight runs in the generic outbound handler before mux/XUDP selection; `freedom.Process` uses the same selector again on the direct path. This ordering prevents shared worker selection from preceding the security decision.

A user mark is selected only when all conditions hold:

- inbound metadata exists;
- `inbound.Name == "vless"`;
- the authenticated user exists;
- `user.Fwmark != 0`.

Freedom attaches the selected value to the dial context as immutable, call-scoped socket policy. A generic outbound dialer consumes that policy without depending on VLESS types. Non-VLESS and non-freedom paths never attach it.

### Per-call settings

The outbound handler must not mutate its shared `h.streamSettings`. For a supported direct transport with a user mark, it creates a call-local copy:

- shallow-copy immutable `MemoryStreamConfig` members;
- protobuf-clone the socket settings, or create them when absent;
- replace `SocketConfig.Mark` with the user mark;
- enable `StrictBinding` on the copied socket settings;
- validate the copied settings before dialing.

The user mark overrides the static outbound mark only in this call-local copy. With `fwmark = 0`, no copy or override is required and the existing static mark behavior remains unchanged.

Every retry on a supported direct transport uses the marked context and newly prepared call-local settings. Direct TCP and UDP follow the same policy.

Marked gRPC transport, Hysteria transport, and SplitHTTP/xhttp are rejected before cloning or reading `DownloadSettings` and before entering their pointer-keyed client caches. Their pooled or lazily mutable lifecycle cannot safely support call-local marks without stable mark-aware ownership, partitioning, reuse, and cleanup; that lifecycle is intentionally not added in RD-35. RD-35 therefore makes no promise that split-download or other pooled multi-socket transports receive per-user marks.

## Mux behavior

Inbound VLESS mux dispatches its inner logical streams independently. Each substream retains `session.Inbound.User`, so outbound selection can derive the same authenticated user's mark for every destination opened by that substream. This inbound metadata preservation remains supported.

Outbound Freedom mux and XUDP are a different boundary: their physical workers are shared and are created independently of a logical flow's authenticated context. A non-zero marked VLESS Freedom flow therefore fails closed before worker creation, reusable-worker selection, or dispatch. RD-35 does not globally disable mux for zero/absent user marks or ordinary/static-mark traffic, and it does not implement mark-partitioned workers in this pull request.

## Fail-closed behavior

A non-zero user mark is mandatory for that freedom dial. The dial fails rather than opening an unmarked socket when:

- the runtime platform is not Linux and therefore cannot provide the required `SO_MARK` semantics;
- the process lacks the capability needed to set `SO_MARK`;
- socket option application fails;
- an alternative system dialer would bypass Xray socket options;
- outbound `proxySettings` or `sockopt.dialerProxy` means freedom does not create the final physical socket;
- outbound Freedom mux or XUDP would create or reuse a shared worker without mark-aware partitioning;
- gRPC transport, Hysteria transport, or SplitHTTP/xhttp would enter a pointer-keyed pooled or lazily mutable transport-client lifecycle;
- a custom socket option would override the mark.

Existing typed strict-binding errors are reused where possible. Errors propagate through the normal freedom/outbound error path. RD-35 does not retry without the mark and does not add success-path logging per socket.

If a copied socket config also contains an interface binding, enabling strict binding makes both route-critical properties mandatory. This avoids a partially applied routing policy.

## Platform behavior

The required and supported production behavior for per-user fwmarks is `runtime.GOOS == "linux"` with `SO_MARK`. A non-zero user fwmark on every other platform returns an explicit strict-binding error. `fwmark = 0` remains portable and unchanged.

Static non-user socket marks retain their existing platform-specific behavior except for the `uint32` type change.

## Test strategy

### Contract and configuration

- Static VLESS JSON accepts an omitted field, `0`, the lower bound, and the upper bound.
- Static VLESS JSON rejects values below the allocated range and outside `uint32`.
- `User -> MemoryUser -> User` preserves `0`, `1_000_000_000`, and `4_294_967_295`.
- Socket JSON and protobuf preserve the full unsigned mark range.

### VLESS and gRPC user management

- VLESS validator accepts `0` and both valid boundaries.
- VLESS validator rejects `1` and `999_999_999` before changing either index.
- `AlterInbound + AddUserOperation` delivers the value to the VLESS user manager.
- Failed dynamic validation leaves the user absent.
- `GetInboundUsers` returns the assigned value.

### Freedom and socket policy

- VLESS with a non-zero fwmark attaches the policy.
- VLESS with zero, a missing user, or a non-VLESS inbound does not attach it.
- The user mark overrides a static mark.
- Zero preserves the static mark.
- Supported direct TCP, UDP, and retry dials receive the same user mark.
- Outbound mux/XUDP, pooled gRPC transport/Hysteria transport/SplitHTTP/xhttp, proxy chains, and other unsupported dial paths fail closed before unsafe worker, clone, cache, or dial activity.

### Isolation and concurrency

- Two simultaneous users with different marks receive different copied socket settings.
- The shared outbound `MemoryStreamConfig` and socket settings remain unchanged for supported direct transports.
- Targeted concurrency tests run with the race detector.
- Existing VLESS mux routing coverage proves inbound logical flows preserve authenticated user metadata with `fwmark = 0` behavior unchanged.
- Marked Freedom mux tests cover both an empty worker pool and an already reusable worker and prove neither is selected; a separate test covers XUDP.
- Marked pooled-transport tests prove gRPC transport, Hysteria transport, and SplitHTTP/xhttp reject before clone/cache access, while zero/static-mark fallback remains unchanged.

### Linux integration

The existing privileged Linux socket test is extended to verify a value above `math.MaxInt32` by reading `SO_MARK` back and comparing its 32-bit representation. It remains skipped by default because it requires `CAP_NET_ADMIN` or an equivalent capability.

## Verification commands

Implementation verification will include focused unit and race tests for:

- `common/protocol`
- `infra/conf`
- `proxy/vless/...`
- `proxy/freedom`
- `app/proxyman/outbound`
- `transport/internet`

The broader affected test set will also run when repository geo assets are available. A missing `resources/geosite.dat` is reported as an environment limitation, not as a passing full-suite result.

## Acceptance criteria

RD-35 is complete when:

1. The backend can send a VLESS user with any valid assigned fwmark through JSON or the existing gRPC add-user operation.
2. Two VLESS UUIDs using the same supported direct Freedom transport can concurrently create outgoing sockets with distinct call-local marks.
3. `4_294_967_295` reaches the Linux socket without sign loss.
4. No shared outbound settings are mutated on supported direct transports; marked pooled/lazy transports are rejected before clone/cache access.
5. Inbound VLESS mux preserves authenticated metadata, while a non-zero marked flow fails closed before outbound Freedom mux/XUDP worker creation, reuse, or dispatch. Zero/absent marks and ordinary/static-mark mux traffic remain unchanged.
6. A non-zero mark can never silently degrade to an unmarked direct connection.
7. Users with `fwmark = 0`, ordinary/static-mark traffic, and unrelated protocols/outbounds retain existing behavior.
