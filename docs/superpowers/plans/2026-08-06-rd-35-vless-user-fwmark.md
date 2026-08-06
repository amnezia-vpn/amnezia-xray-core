# RD-35 VLESS User Fwmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mark every supported direct socket created by `freedom` for an authenticated VLESS user with the backend-assigned per-user fwmark.

**Architecture:** Add `fwmark` to the shared protobuf user contract, validate it at VLESS boundaries, and carry it from `session.Inbound.User` into an immutable dial-context value selected only by Freedom. A narrow optional proxy preflight prepares that context before outbound mux/XUDP selection. Marked Freedom mux/XUDP and pointer-keyed pooled/lazy transports fail closed before unsafe worker, clone, cache, or dial activity; supported direct transports consume a call-local settings clone with strict binding so failure can never fall back to an unmarked socket.

**Tech Stack:** Go 1.26, protobuf/protoc, Xray gRPC `HandlerService.AlterInbound`, Linux `SO_MARK`, Go `testing`, race detector.

## Global Constraints

- Work on `frog/rd-35-user-fwmark`, based on `frog/external-user-routing`.
- Preserve the user's unrelated `.gitignore` modification; never stage it.
- Use FrogRocky `<269552296+FrogRocky@users.noreply.github.com>` for Amnezia commits.
- Valid per-user values are exactly `0` or `1_000_000_000..4_294_967_295` inclusive.
- The backend allocates and guarantees worker-domain uniqueness; Xray neither allocates nor persists marks.
- Per-user marking applies only to authenticated VLESS traffic handled by direct `freedom`.
- `fwmark = 0` is backward compatible and does not override a static socket mark.
- A non-zero user mark overrides the static mark only in a call-local socket-settings clone.
- A non-zero user mark is Linux-only and fail-closed: no unsupported, bypassed, or failed path may open an unmarked socket.
- Do not globally disable or repartition mux, and do not create per-user outbounds or pools. A non-zero marked VLESS Freedom flow must nevertheless fail closed before outbound mux/XUDP worker creation, reuse, or dispatch.
- Marked gRPC transport, Hysteria transport, and SplitHTTP/xhttp fail closed before settings clone/cache access; RD-35 does not add mark-aware pooled-client ownership, reuse, or cleanup.
- Change the shared transport socket mark from `int32` to `uint32`; existing non-negative protobuf values retain their wire meaning.
- RD-37 device/IP enforcement and RD-36 profiling remain out of scope.

---

## File Map

### Contract and generated code

- `common/protocol/user.proto`: add the VLESS user `fwmark` field.
- `common/protocol/user.pb.go`: generated Go representation and getter.
- `common/protocol/user.go`: copy `Fwmark` between protobuf and memory users.
- `transport/internet/config.proto`: change `SocketConfig.mark` to `uint32`.
- `transport/internet/config.pb.go`: generated unsigned socket mark.

### Validation and JSON/gRPC boundaries

- `proxy/vless/user_fwmark.go`: constants and the reusable VLESS mark validator.
- `proxy/vless/validator.go`: validate before changing UUID/email indexes.
- `infra/conf/vless.go`: reject invalid static VLESS JSON during build.
- `infra/conf/vless_test.go`: static JSON boundary coverage.
- `proxy/vless/user_fwmark_test.go`: validation and user round-trip coverage.
- `app/proxyman/command/user_fwmark_test.go`: protobuf round-trip for the existing gRPC add-user operation.

### Socket-mark propagation

- `common/session/context.go`: immutable outbound socket-mark context helpers.
- `common/session/session.go`: unsigned internal socket mark.
- `common/session/context_test.go`: context and mux preservation tests.
- `app/proxyman/outbound/socket_mark.go`: validate supported transports, then create call-local stream/socket settings and override the mark.
- `app/proxyman/outbound/socket_mark_test.go`: override, isolation, concurrency, and pooled-transport fail-closed tests.
- `app/proxyman/outbound/handler.go`: run optional proxy preflight, reject marked mux/XUDP and proxy-chain bypass, and consume the call-scoped mark on supported direct paths.
- `app/proxyman/outbound/handler_test.go`: dynamic strict-binding bypass coverage.
- `app/proxyman/outbound/user_fwmark_mux_test.go`: new/reusable mux, XUDP, direct, and unchanged-fallback coverage.
- `proxy/proxy.go`: optional `OutboundContextPreparer` capability used before dispatch-path selection.
- `proxy/freedom/user_fwmark.go`: select a mark only from authenticated VLESS sessions and expose the optional preflight.
- `proxy/freedom/user_fwmark_test.go`: selection matrix.
- `proxy/freedom/freedom.go`: preserve direct-path selection before each Freedom dial/retry.

### Unsigned mark consumers and integration checks

- `infra/conf/transport_internet.go`: parse the full unsigned JSON range.
- `infra/conf/transport_test.go`: maximum mark and negative rejection.
- `transport/internet/sockopt.go`: convert unsigned marks to the exact 32-bit syscall representation.
- `transport/internet/sockopt_linux.go`: preserve the unsigned 32-bit mark at `setsockopt`.
- `transport/internet/sockopt_freebsd.go`: compile-safe unsigned conversion for the existing static cookie behavior.
- `transport/internet/sockopt_linux_test.go`: privileged maximum-value readback.
- `proxy/dokodemo/dokodemo.go`: compile-safe conversion of the unsigned session mark.
- `app/proxyman/inbound/inbound.go`: propagate the unsigned static listener mark.
- Existing transport cache implementations remain behaviorally unchanged; marked gRPC transport, Hysteria transport, and SplitHTTP/xhttp are rejected before reaching them, while zero/static-mark traffic is included in regression tests.

---

### Task 1: Support the full unsigned socket-mark range

**Files:**
- Modify: `transport/internet/config.proto:104-109`
- Regenerate: `transport/internet/config.pb.go`
- Modify: `infra/conf/transport_internet.go:1066-1069`
- Modify: `common/session/session.go:104-109`
- Modify: `transport/internet/sockopt.go`
- Modify: `transport/internet/sockopt_linux.go:16-21,115-120`
- Modify: `transport/internet/sockopt_freebsd.go:127-131,180-184`
- Modify: `proxy/dokodemo/dokodemo.go:176-184`
- Modify: `app/proxyman/inbound/inbound.go:168-177`
- Modify: `infra/conf/transport_test.go`
- Modify: `transport/internet/sockopt_linux_test.go`

**Interfaces:**
- Produces: `internet.SocketConfig.Mark uint32` and `session.Sockopt.Mark uint32`.
- Preserves: protobuf field number `SocketConfig.mark = 1` and all existing strict-binding semantics.

- [ ] **Step 1: Add failing unsigned configuration tests**

Add a named subtest to `TestSocketConfig` in `infra/conf/transport_test.go`:

```go
t.Run("full unsigned mark", func(t *testing.T) {
	config := new(SocketConfig)
	if err := json.Unmarshal([]byte(`{"mark":4294967295}`), config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	if built.Mark != uint32(math.MaxUint32) {
		t.Fatalf("mark = %d, want %d", built.Mark, uint32(math.MaxUint32))
	}
})

t.Run("negative mark rejected", func(t *testing.T) {
	config := new(SocketConfig)
	if err := json.Unmarshal([]byte(`{"mark":-1}`), config); err == nil {
		t.Fatal("negative mark unexpectedly accepted")
	}
})
```

Add `math` to the test imports. Change the privileged test constant in `transport/internet/sockopt_linux_test.go` to:

```go
const mark = uint32(math.MaxUint32)
```

Compare the kernel result by bit representation:

```go
if uint32(m) != mark {
	t.Fatalf("connection mark = %d, want %d", uint32(m), mark)
}
```

- [ ] **Step 2: Run the tests and verify the old signed contract fails**

Run:

```bash
go test ./infra/conf ./transport/internet -run 'TestSocketConfig|TestSockOptMark' -count=1
```

Expected: FAIL to compile because `4_294_967_295` cannot be represented by the current `int32` mark fields. `TestSockOptMark` remains skipped without `CAP_NET_ADMIN` after compilation is repaired.

- [ ] **Step 3: Change the protobuf and runtime types to `uint32`**

Change the field without changing its number:

```proto
// Mark of the connection. If non-zero, the value will be set to SO_MARK.
uint32 mark = 1;
```

Change the JSON and in-memory fields:

```go
Mark uint32 `json:"mark"`
```

```go
type Sockopt struct {
	Mark uint32
}
```

Add the conversion helper to the platform-neutral `transport/internet/sockopt.go`. At `SetsockoptInt` boundaries, it explicitly preserves the 32-bit representation on both 32-bit and 64-bit builds:

```go
func socketMarkValue(mark uint32) int {
	return int(int32(mark))
}
```

Use `socketMarkValue(config.Mark)` for Linux `SO_MARK` and FreeBSD `SO_USER_COOKIE`. Use `int(int32(d.sockopt.Mark))` at the dokodemo ancillary-data boundary.

- [ ] **Step 4: Regenerate only the changed transport protobuf**

Run:

```bash
PATH=/Users/ilyam/go/bin:$PATH protoc --go_out=. --go_opt=paths=source_relative transport/internet/config.proto
```

Expected: `transport/internet/config.pb.go` contains `Mark uint32` and `GetMark() uint32`; unrelated generated files do not change.

- [ ] **Step 5: Format and run affected tests**

Run:

```bash
gofmt -w infra/conf/transport_internet.go infra/conf/transport_test.go common/session/session.go transport/internet/sockopt.go transport/internet/sockopt_linux.go transport/internet/sockopt_freebsd.go transport/internet/sockopt_linux_test.go proxy/dokodemo/dokodemo.go app/proxyman/inbound/inbound.go
go test ./infra/conf ./transport/internet ./transport/internet/splithttp ./proxy/dokodemo ./app/proxyman/inbound -count=1
```

Expected: PASS; the privileged `SO_MARK` test reports SKIP unless the process has the required capability.

- [ ] **Step 6: Commit the unsigned transport contract**

```bash
git add transport/internet/config.proto transport/internet/config.pb.go infra/conf/transport_internet.go infra/conf/transport_test.go common/session/session.go transport/internet/sockopt.go transport/internet/sockopt_linux.go transport/internet/sockopt_freebsd.go transport/internet/sockopt_linux_test.go proxy/dokodemo/dokodemo.go app/proxyman/inbound/inbound.go
git commit -m "Support unsigned socket marks"
```

Verify `git status --short` still lists `.gitignore` as unstaged.

---

### Task 2: Add and validate the VLESS user fwmark contract

**Files:**
- Modify: `common/protocol/user.proto`
- Regenerate: `common/protocol/user.pb.go`
- Modify: `common/protocol/user.go`
- Create: `proxy/vless/user_fwmark.go`
- Modify: `proxy/vless/validator.go`
- Create: `proxy/vless/user_fwmark_test.go`
- Modify: `infra/conf/vless.go`
- Modify: `infra/conf/vless_test.go`
- Create: `app/proxyman/command/user_fwmark_test.go`

**Interfaces:**
- Produces: `protocol.User.Fwmark uint32`, `protocol.MemoryUser.Fwmark uint32`.
- Produces: `vless.MinUserFwmark uint32 = 1_000_000_000`.
- Produces: `vless.ValidateUserFwmark(mark uint32) error`.
- Consumed later by: `freedom.contextWithVLESSUserFwmark` in Task 4.

- [ ] **Step 1: Add failing VLESS boundary and round-trip tests**

Create `proxy/vless/user_fwmark_test.go` in package `vless` with table-driven validation:

```go
func TestValidateUserFwmark(t *testing.T) {
	tests := []struct {
		name    string
		mark    uint32
		wantErr bool
	}{
		{name: "disabled", mark: 0},
		{name: "below range", mark: 999_999_999, wantErr: true},
		{name: "minimum", mark: 1_000_000_000},
		{name: "maximum", mark: math.MaxUint32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateUserFwmark(test.mark)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateUserFwmark(%d) error = %v, wantErr %v", test.mark, err, test.wantErr)
			}
		})
	}
}
```

Add an atomic-rejection test in the same file:

```go
func TestMemoryValidatorRejectsInvalidFwmarkWithoutMutation(t *testing.T) {
	id := uuid.New()
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{ID: protocol.NewID(id)},
		Email:   "invalid-fwmark@example.com",
		Fwmark:  999_999_999,
	}
	validator := new(MemoryValidator)
	if err := validator.Add(user); err == nil {
		t.Fatal("invalid fwmark unexpectedly accepted")
	}
	if validator.GetCount() != 0 {
		t.Fatalf("user count = %d, want 0", validator.GetCount())
	}
	if got := validator.GetByEmail(user.Email); got != nil {
		t.Fatalf("email index contains rejected user: %+v", got)
	}
	if got := validator.Get(id); got != nil {
		t.Fatalf("uuid index contains rejected user: %+v", got)
	}
}
```

Add the protobuf-memory-protobuf round trip:

```go
func TestUserFwmarkRoundTrip(t *testing.T) {
	original := &protocol.User{
		Account: serial.ToTypedMessage(&Account{Id: uuid.New().String()}),
		Fwmark:  math.MaxUint32,
	}
	memoryUser, err := original.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	if memoryUser.Fwmark != uint32(math.MaxUint32) {
		t.Fatalf("memory fwmark = %d, want %d", memoryUser.Fwmark, uint32(math.MaxUint32))
	}
	roundTrip := protocol.ToProtoUser(memoryUser)
	if roundTrip.GetFwmark() != uint32(math.MaxUint32) {
		t.Fatalf("protobuf fwmark = %d, want %d", roundTrip.GetFwmark(), uint32(math.MaxUint32))
	}
}
```

Add static JSON tests to `infra/conf/vless_test.go`:

```go
func TestVLessInboundFwmark(t *testing.T) {
	tests := []struct {
		name         string
		fwmarkField  string
		want         uint32
		wantBuildErr bool
	}{
		{name: "omitted"},
		{name: "disabled", fwmarkField: `,"fwmark":0`},
		{name: "negative", fwmarkField: `,"fwmark":-1`, wantBuildErr: true},
		{name: "below range", fwmarkField: `,"fwmark":999999999`, wantBuildErr: true},
		{name: "minimum", fwmarkField: `,"fwmark":1000000000`, want: 1_000_000_000},
		{name: "maximum", fwmarkField: `,"fwmark":4294967295`, want: math.MaxUint32},
		{name: "above uint32", fwmarkField: `,"fwmark":4294967296`, wantBuildErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := fmt.Sprintf(`{"clients":[{"id":"27848739-7e62-4138-9fd3-098a63964b6b"%s}],"decryption":"none"}`, test.fwmarkField)
			config := new(VLessInboundConfig)
			if err := json.Unmarshal([]byte(input), config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if test.wantBuildErr {
				if err == nil {
					t.Fatal("Build() unexpectedly succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := built.(*inbound.Config).Users[0].Fwmark; got != test.want {
				t.Fatalf("fwmark = %d, want %d", got, test.want)
			}
		})
	}
}
```

Create `app/proxyman/command/user_fwmark_test.go` and protobuf-round-trip the actual add-user operation:

```go
func TestAddUserOperationFwmarkRoundTrip(t *testing.T) {
	original := &AddUserOperation{User: &protocol.User{Fwmark: math.MaxUint32}}
	wire, err := proto.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(AddUserOperation)
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetUser().GetFwmark() != uint32(math.MaxUint32) {
		t.Fatalf("fwmark = %d, want %d", decoded.GetUser().GetFwmark(), uint32(math.MaxUint32))
	}
}
```

- [ ] **Step 2: Run the tests and verify the missing field/API fails**

Run:

```bash
go test ./proxy/vless ./infra/conf ./app/proxyman/command -run 'Fwmark' -count=1
```

Expected: FAIL to compile because `Fwmark`, `ValidateUserFwmark`, and `GetFwmark` do not exist.

- [ ] **Step 3: Add the protobuf and memory-user field**

Add field number 4:

```proto
uint32 fwmark = 4;
```

Copy it into and out of memory users:

```go
return &MemoryUser{
	Account: account,
	Email:   u.Email,
	Level:   u.Level,
	Fwmark:  u.Fwmark,
}, nil
```

```go
return &User{
	Account: serial.ToTypedMessage(mu.Account.ToProto()),
	Email:   mu.Email,
	Level:   mu.Level,
	Fwmark:  mu.Fwmark,
}
```

Add the runtime field:

```go
type MemoryUser struct {
	Account Account
	Email   string
	Level   uint32
	Fwmark  uint32
}
```

- [ ] **Step 4: Regenerate only the changed user protobuf**

Run:

```bash
PATH=/Users/ilyam/go/bin:$PATH protoc --go_out=. --go_opt=paths=source_relative common/protocol/user.proto
```

Expected: `common/protocol/user.pb.go` contains `Fwmark uint32` and `GetFwmark() uint32`.

- [ ] **Step 5: Implement one validator used by static and dynamic VLESS paths**

Create `proxy/vless/user_fwmark.go`:

```go
package vless

import "github.com/xtls/xray-core/common/errors"

const MinUserFwmark uint32 = 1_000_000_000

func ValidateUserFwmark(mark uint32) error {
	if mark != 0 && mark < MinUserFwmark {
		return errors.New("VLESS user fwmark must be zero or at least ", MinUserFwmark).AtError()
	}
	return nil
}
```

Call it at the start of `MemoryValidator.Add`, before `email.LoadOrStore`:

```go
if err := ValidateUserFwmark(u.Fwmark); err != nil {
	return err
}
```

Call it in `VLessInboundConfig.Build` immediately after unmarshalling the raw object into `protocol.User`:

```go
if err := vless.ValidateUserFwmark(user.Fwmark); err != nil {
	return errors.New("VLESS users: invalid fwmark").Base(err)
}
```

The protobuf type itself enforces the upper bound. Do not add a uniqueness index.

- [ ] **Step 6: Format and run contract tests**

Run:

```bash
gofmt -w common/protocol/user.go proxy/vless/user_fwmark.go proxy/vless/validator.go proxy/vless/user_fwmark_test.go infra/conf/vless.go infra/conf/vless_test.go app/proxyman/command/user_fwmark_test.go
go test ./common/protocol ./proxy/vless ./infra/conf ./app/proxyman/command -count=1
```

Expected: PASS. Confirm `GetInboundUsers` requires no method change because it already calls `protocol.ToProtoUser`.

- [ ] **Step 7: Commit the user/API contract**

```bash
git add common/protocol/user.proto common/protocol/user.pb.go common/protocol/user.go proxy/vless/user_fwmark.go proxy/vless/validator.go proxy/vless/user_fwmark_test.go infra/conf/vless.go infra/conf/vless_test.go app/proxyman/command/user_fwmark_test.go
git commit -m "Add fwmark to VLESS users"
```

Verify `.gitignore` remains unstaged.

---

### Task 3: Add isolated call-scoped socket-mark settings

**Files:**
- Modify: `common/session/context.go`
- Create: `common/session/context_test.go`
- Create: `app/proxyman/outbound/socket_mark.go`
- Create: `app/proxyman/outbound/socket_mark_test.go`
- Modify: `app/proxyman/outbound/handler.go`
- Modify: `app/proxyman/outbound/handler_test.go`

**Interfaces:**
- Produces: `session.ContextWithOutboundSocketMark(ctx context.Context, mark uint32) context.Context`.
- Produces: `session.OutboundSocketMarkFromContext(ctx context.Context) uint32`.
- Produces internally: `streamSettingsWithOutboundSocketMark(settings *internet.MemoryStreamConfig, mark uint32) (*internet.MemoryStreamConfig, error)`.
- Produces internally: `validateUserSocketMarkTransport(settings *internet.MemoryStreamConfig, mark uint32) error`.
- Produces internally: `validateUserSocketMarkPlatform(platform string) error`.
- Consumes: `internet.ValidateStrictBinding` and the existing `internet.NewStrictBindingBypassError`.

- [ ] **Step 1: Add failing context and cloning tests**

Create `common/session/context_test.go` with:

```go
func TestOutboundSocketMarkContext(t *testing.T) {
	ctx := ContextWithOutboundSocketMark(context.Background(), math.MaxUint32)
	if got := OutboundSocketMarkFromContext(ctx); got != uint32(math.MaxUint32) {
		t.Fatalf("mark = %d, want %d", got, uint32(math.MaxUint32))
	}
	if got := OutboundSocketMarkFromContext(context.Background()); got != 0 {
		t.Fatalf("unset mark = %d, want 0", got)
	}
}
```

Create `app/proxyman/outbound/socket_mark_test.go` in package `outbound` and verify supported direct-settings isolation:

```go
func TestStreamSettingsWithOutboundSocketMarkIsIsolated(t *testing.T) {
	baseSocket := &internet.SocketConfig{Mark: 7, TcpKeepAliveInterval: 11}
	downloadSocket := &internet.SocketConfig{Mark: 8, TcpKeepAliveIdle: 13}
	base := &internet.MemoryStreamConfig{
		ProtocolName:   "tcp",
		SocketSettings: baseSocket,
		DownloadSettings: &internet.MemoryStreamConfig{
			ProtocolName:   "tcp",
			SocketSettings: downloadSocket,
		},
	}

	got, err := streamSettingsWithOutboundSocketMark(base, math.MaxUint32)
	if err != nil {
		t.Fatal(err)
	}
	if got == base || got.SocketSettings == baseSocket || got.DownloadSettings == base.DownloadSettings {
		t.Fatal("stream settings were not deeply isolated")
	}
	if got.SocketSettings.Mark != uint32(math.MaxUint32) || !got.SocketSettings.StrictBinding {
		t.Fatalf("primary socket = %+v", got.SocketSettings)
	}
	if baseSocket.Mark != 7 || baseSocket.StrictBinding {
		t.Fatalf("base socket was mutated: %+v", baseSocket)
	}
	if downloadSocket.Mark != 8 || downloadSocket.StrictBinding {
		t.Fatalf("download socket was mutated: %+v", downloadSocket)
	}
}
```

The nested direct-settings fixture verifies defensive clone isolation; it is not a promise that marked SplitHTTP/xhttp is supported. Add a table case for nil settings and a concurrent test that creates two supported direct clones with marks `1_000_000_000` and `1_000_000_001`, checks their values, and then checks the shared base remains unchanged. Run that test with `-race` in Step 5.

Add fail-closed cases for `grpc`, `hysteria`, and `splithttp`. Assert that a non-zero user mark returns `StrictBindingConfigBypass` before cloning or entering a pointer-keyed transport cache. For SplitHTTP, race a test-only `DownloadSettings` mutation against repeated marked calls and prove the preflight rejection occurs before reading that shared lazy field. Add controls showing `tcp` and `udp` remain supported and mark `0` preserves static pooled-transport behavior.

Add a platform table test:

```go
func TestValidateUserSocketMarkPlatform(t *testing.T) {
	if err := validateUserSocketMarkPlatform("linux"); err != nil {
		t.Fatalf("linux validation failed: %v", err)
	}
	for _, platform := range []string{"android", "darwin", "freebsd", "windows"} {
		t.Run(platform, func(t *testing.T) {
			var configErr *internet.StrictBindingConfigError
			if err := validateUserSocketMarkPlatform(platform); !errors.As(err, &configErr) || configErr.Kind != internet.StrictBindingConfigUnsupportedOption {
				t.Fatalf("error = %T %v, want unsupported-option error", err, err)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests and verify the context/helper is missing**

Run:

```bash
go test ./common/session ./app/proxyman/outbound -run 'OutboundSocketMark|StreamSettingsWithOutboundSocketMark' -count=1
```

Expected: FAIL to compile because the new context functions and clone helper do not exist.

- [ ] **Step 3: Add immutable context helpers**

Allocate the next `ctx.SessionKey` after `streamSettingsKey` and add:

```go
func ContextWithOutboundSocketMark(ctx context.Context, mark uint32) context.Context {
	return context.WithValue(ctx, outboundSocketMarkKey, mark)
}

func OutboundSocketMarkFromContext(ctx context.Context) uint32 {
	if mark, ok := ctx.Value(outboundSocketMarkKey).(uint32); ok {
		return mark
	}
	return 0
}
```

The stored value is a scalar and immutable. Do not reuse `session.Sockopt`, which represents inbound listener metadata.

- [ ] **Step 4: Implement validated per-call cloning and handler consumption**

Create `app/proxyman/outbound/socket_mark.go` in package `outbound`:

```go
package outbound

import (
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func cloneMemoryStreamConfig(settings *internet.MemoryStreamConfig) *internet.MemoryStreamConfig {
	if settings == nil {
		return nil
	}
	cloned := *settings
	if settings.SocketSettings != nil {
		cloned.SocketSettings = proto.Clone(settings.SocketSettings).(*internet.SocketConfig)
	}
	cloned.DownloadSettings = cloneMemoryStreamConfig(settings.DownloadSettings)
	return &cloned
}

func streamSettingsWithOutboundSocketMark(settings *internet.MemoryStreamConfig, mark uint32) (*internet.MemoryStreamConfig, error) {
	if err := validateUserSocketMarkTransport(settings, mark); err != nil {
		return nil, err
	}
	if settings == nil {
		var err error
		settings, err = internet.ToMemoryStreamConfig(nil)
		if err != nil {
			return nil, err
		}
	}
	cloned := cloneMemoryStreamConfig(settings)
	if cloned.SocketSettings == nil {
		cloned.SocketSettings = new(internet.SocketConfig)
	}
	cloned.SocketSettings.Mark = mark
	cloned.SocketSettings.StrictBinding = true
	return cloned, nil
}

func validateUserSocketMarkTransport(settings *internet.MemoryStreamConfig, mark uint32) error {
	if mark == 0 || settings == nil {
		return nil
	}

	switch settings.ProtocolName {
	case "grpc", "hysteria", "splithttp":
		return internet.NewStrictBindingBypassError(settings.ProtocolName + " transport client pool")
	default:
		return nil
	}
}

func validateUserSocketMarkPlatform(platform string) error {
	if platform == "linux" {
		return nil
	}
	return &internet.StrictBindingConfigError{
		Kind:     internet.StrictBindingConfigUnsupportedOption,
		Option:   internet.SocketBindingOptionMark,
		Platform: platform,
	}
}
```

At the start of `Handler.Dial`, read the mark. Before dispatching through `senderSettings.ProxySettings`, reject that bypass:

```go
socketMark := session.OutboundSocketMarkFromContext(ctx)
if socketMark != 0 && h.senderSettings != nil && h.senderSettings.ProxySettings.HasTag() {
	return nil, internet.NewStrictBindingBypassError("outbound proxySettings")
}
if socketMark != 0 {
	if err := validateUserSocketMarkTransport(h.streamSettings, socketMark); err != nil {
		return nil, err
	}
	if err := validateUserSocketMarkPlatform(runtime.GOOS); err != nil {
		return nil, err
	}
}
```

Before the existing direct `internet.Dial`, prepare and validate only the call-local settings:

```go
streamSettings := h.streamSettings
if socketMark != 0 {
	var err error
	streamSettings, err = streamSettingsWithOutboundSocketMark(streamSettings, socketMark)
	if err != nil {
		return nil, errors.New("failed to prepare user socket mark").Base(err)
	}
	if err := internet.ValidateStrictBinding(streamSettings.SocketSettings); err != nil {
		return nil, err
	}
}

conn, err := internet.Dial(ctx, dest, streamSettings)
```

Transport validation runs before cloning and therefore before any pointer-keyed pool/cache access or lazy `DownloadSettings` read. This leaves `h.streamSettings` unchanged. Existing `DialSystem` validation rejects `dialerProxy`, custom conflicts, and alternative system dialers after `StrictBinding` is enabled for supported direct transports.

- [ ] **Step 5: Add and run fail-closed handler tests**

Extend `app/proxyman/outbound/handler_test.go` with a handler whose `proxySettings` chain is allowed at construction time because its static config is not strict. Put a non-zero mark into the dial context and assert that `Handler.Dial` returns `StrictBindingConfigBypass` before dispatching. In `socket_mark_test.go`, assert marked gRPC transport, Hysteria transport, and SplitHTTP/xhttp reject before clone/cache access and that supported direct and zero/static fallback controls remain unchanged.

Run:

```bash
gofmt -w common/session/context.go common/session/context_test.go app/proxyman/outbound/socket_mark.go app/proxyman/outbound/socket_mark_test.go app/proxyman/outbound/handler.go app/proxyman/outbound/handler_test.go
go test ./common/session ./app/proxyman/outbound -count=1
go test -race ./common/session ./app/proxyman/outbound -run 'OutboundSocketMark|StreamSettingsWithOutboundSocketMark|UserMark|PooledTransport|SplitHTTP' -count=1
```

Expected: PASS on all platforms. On non-Linux, a marked supported direct dial is rejected by the explicit per-user platform check. Marked pooled transports fail before cloning on every platform. Static/zero-mark behavior is unchanged and direct-cloning tests remain platform independent.

- [ ] **Step 6: Commit call-scoped mark isolation**

```bash
git add common/session/context.go common/session/context_test.go app/proxyman/outbound/socket_mark.go app/proxyman/outbound/socket_mark_test.go app/proxyman/outbound/handler.go app/proxyman/outbound/handler_test.go
git commit -m "Add isolated outbound socket marks"
```

Verify `.gitignore` remains unstaged.

---

### Task 4: Apply authenticated VLESS marks from Freedom and preflight shared workers

**Files:**
- Create: `proxy/freedom/user_fwmark.go`
- Create: `proxy/freedom/user_fwmark_test.go`
- Modify: `proxy/freedom/freedom.go:267-360`
- Modify: `common/session/context_test.go`
- Modify: `proxy/proxy.go`
- Modify: `app/proxyman/outbound/handler.go`
- Create: `app/proxyman/outbound/user_fwmark_mux_test.go`

**Interfaces:**
- Consumes: `protocol.MemoryUser.Fwmark` from Task 2.
- Consumes: `session.ContextWithOutboundSocketMark` from Task 3.
- Produces internally: `contextWithVLESSUserFwmark(ctx context.Context) context.Context`.
- Produces: optional `proxy.OutboundContextPreparer`, implemented only by Freedom, so the handler can prepare security context before dispatch-path selection.
- Leaves the existing `internet.Dialer` interface unchanged.

- [ ] **Step 1: Add failing freedom selection tests**

Create `proxy/freedom/user_fwmark_test.go` in package `freedom`:

```go
func TestContextWithVLESSUserFwmark(t *testing.T) {
	tests := []struct {
		name     string
		inbound  *session.Inbound
		wantMark uint32
	}{
		{name: "missing inbound"},
		{name: "missing user", inbound: &session.Inbound{Name: "vless"}},
		{name: "disabled", inbound: &session.Inbound{Name: "vless", User: &protocol.MemoryUser{Fwmark: 0}}},
		{name: "other protocol", inbound: &session.Inbound{Name: "vmess", User: &protocol.MemoryUser{Fwmark: 1_000_000_000}}},
		{name: "vless", inbound: &session.Inbound{Name: "vless", User: &protocol.MemoryUser{Fwmark: math.MaxUint32}}, wantMark: math.MaxUint32},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.inbound != nil {
				ctx = session.ContextWithInbound(ctx, test.inbound)
			}
			ctx = contextWithVLESSUserFwmark(ctx)
			if got := session.OutboundSocketMarkFromContext(ctx); got != test.wantMark {
				t.Fatalf("mark = %d, want %d", got, test.wantMark)
			}
		})
	}
}
```

Extend `common/session/context_test.go` so `SubContextFromMuxInbound` is given an inbound containing a `MemoryUser{Fwmark: 1_000_000_000}` and assert that `InboundFromContext(child).User.Fwmark` remains unchanged.

Create `app/proxyman/outbound/user_fwmark_mux_test.go` with handler-boundary regressions that prove:

- marked VLESS + Freedom + outbound mux rejects before creating a worker when none exists;
- the same flow rejects before selecting or dispatching an already reusable worker;
- marked VLESS + Freedom + XUDP rejects before worker creation;
- a prepared mark continues into the ordinary direct path;
- zero user mark with static-mark fallback, non-VLESS inbound metadata, and non-Freedom outbounds retain existing mux selection.

- [ ] **Step 2: Run the tests and verify freedom does not select marks yet**

Run:

```bash
go test ./proxy/freedom ./common/session -run 'VLESSUserFwmark|MuxInbound' -count=1
```

Expected: RED. The selector initially fails to compile because `contextWithVLESSUserFwmark` does not exist. Before the preflight integration, the handler regressions show mux/XUDP worker creation or selection and show that the direct path has not received the prepared mark.

- [ ] **Step 3: Implement the freedom-only selector**

Create `proxy/freedom/user_fwmark.go` with the selector and Freedom's optional preflight:

```go
package freedom

import (
	"context"

	"github.com/xtls/xray-core/common/session"
)

func contextWithVLESSUserFwmark(ctx context.Context) context.Context {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.Name != "vless" || inbound.User == nil || inbound.User.Fwmark == 0 {
		return ctx
	}
	return session.ContextWithOutboundSocketMark(ctx, inbound.User.Fwmark)
}

func (*Handler) PrepareOutboundContext(ctx context.Context) context.Context {
	return contextWithVLESSUserFwmark(ctx)
}
```

Add the narrow optional interface to `proxy/proxy.go`:

```go
type OutboundContextPreparer interface {
	PrepareOutboundContext(context.Context) context.Context
}
```

At the start of `app/proxyman/outbound.Handler.Dispatch`, invoke that capability before any mux/XUDP manager call. Record a required mark only for a proxy that implements the capability. If an enabled outbound mux or XUDP path would be selected with a non-zero required mark, return a typed strict-binding bypass through the normal outbound error path before calling its picker or manager. Do not create mark-partitioned workers in RD-35.

In `freedom.Process`, after obtaining `inbound` and before entering `retry.ExponentialBackoff`, reuse the same preflight method:

```go
inbound := session.InboundFromContext(ctx)
ctx = h.PrepareOutboundContext(ctx)
defaultRule := getDefaultFinalRule(inbound)
```

All supported direct retry attempts already call `dialer.Dial(ctx, dialDest)`, so they reuse the immutable marked context without changing the dialer interface. Inbound VLESS mux metadata preservation remains supported; outbound Freedom mux/XUDP sharing with a non-zero user mark is explicitly unsupported and fails closed before worker creation, reuse, or dispatch.

- [ ] **Step 4: Run freedom, mux, and race regressions**

Run:

```bash
gofmt -w proxy/proxy.go proxy/freedom/user_fwmark.go proxy/freedom/user_fwmark_test.go proxy/freedom/freedom.go common/session/context_test.go app/proxyman/outbound/handler.go app/proxyman/outbound/user_fwmark_mux_test.go
go test ./proxy/freedom ./common/session ./common/mux ./app/proxyman/outbound -count=1
go test -race ./app/proxyman/outbound -run 'MarkedVLESSFreedomRejects|FreedomMuxFallback|PreparedUserMark|UserMark|StreamSettingsWithOutboundSocketMark' -count=1
go test -race ./proxy/freedom ./common/session ./common/mux -count=1
go test ./testing/scenarios -run '^(TestVlessMuxUserDestinationRouting|TestVMessGCMMux|TestVMessGCMMuxUDP)$' -count=1
```

Expected: PASS. The VLESS scenario proves inbound mux routing remains unchanged with `fwmark = 0`; the session test proves child contexts retain authenticated user metadata; the handler tests prove non-zero marked Freedom flows cannot create, select, or dispatch outbound mux/XUDP workers. VMess mux/XUDP scenarios prove unrelated protocols retain existing behavior.

- [ ] **Step 5: Run Linux-specific build and privileged test instructions**

On every development platform, compile the Linux test binary without running it:

```bash
GOOS=linux GOARCH=amd64 go test ./transport/internet -run '^TestSockOptMark$' -c -o /tmp/xray-internet-linux.test
```

On a Linux worker with the required capability, run:

```bash
go test ./transport/internet -run '^TestSockOptMark$' -count=1
```

Expected on the privileged worker: PASS and `4_294_967_295` is read back from `SO_MARK` without sign loss. Expected elsewhere: the source test remains explicitly skipped.

- [ ] **Step 6: Commit freedom integration**

```bash
git add proxy/proxy.go proxy/freedom/user_fwmark.go proxy/freedom/user_fwmark_test.go proxy/freedom/freedom.go common/session/context_test.go app/proxyman/outbound/handler.go app/proxyman/outbound/user_fwmark_mux_test.go
git commit -m "Apply VLESS user marks in freedom"
```

Verify `.gitignore` remains unstaged.

---

## Final Verification

- [ ] Run protobuf and configuration tests:

```bash
go test ./common/protocol ./infra/conf ./app/proxyman/command -count=1
```

- [ ] Run VLESS, Freedom, outbound-handler, mux, session, and transport tests:

```bash
go test ./proxy/vless/... ./proxy/freedom ./app/proxyman/outbound ./common/mux ./common/session ./transport/internet ./transport/internet/splithttp -count=1
```

- [ ] Run focused race-sensitive user-mark, pooled-transport, and mux packages:

```bash
go test -race ./app/proxyman/outbound -run 'MarkedVLESSFreedomRejects|FreedomMuxFallback|PreparedUserMark|UserMark|StreamSettingsWithOutboundSocketMark|PooledTransport|SplitHTTP' -count=1
go test -race ./proxy/vless ./proxy/vless/inbound ./proxy/freedom ./common/session ./common/mux ./transport/internet -count=1
```

The repository's broader `app/proxyman/outbound` race run may still report the known unrelated `TestTagsCache` manager race. Record it separately; do not treat it as a user-mark pass or expand RD-35 into that manager fix.

- [ ] Run inbound VLESS mux plus unrelated VMess mux/XUDP scenarios:

```bash
go test ./testing/scenarios -run '^(TestVlessMuxUserDestinationRouting|TestVMessGCMMux|TestVMessGCMMuxUDP)$' -count=1
```

The VLESS scenario covers preserved inbound mux metadata and zero-mark behavior. Marked outbound Freedom mux/XUDP rejection is covered by `user_fwmark_mux_test.go`, including empty and reusable worker states.

- [ ] Run a broader repository test if geo assets are present:

```bash
go test ./... -count=1
```

If `resources/geosite.dat` or another required asset is missing, record that environment limitation separately; do not report the full suite as passing.

- [ ] Review the complete branch diff and generated files:

```bash
git diff frog/external-user-routing...HEAD --check
git diff frog/external-user-routing...HEAD --stat
git status --short
```

Expected: only RD-35 specification, plan, implementation, tests, and required generated protobuf changes are in the branch; `.gitignore` remains an unstaged user modification.

- [ ] Confirm the branch contains the primary Task 1–4 implementation commits plus the scoped final-review safety and documentation commits, then prepare the RD-35 pull request. Do not start RD-37 until RD-35 verification is complete.
