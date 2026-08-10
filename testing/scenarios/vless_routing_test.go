package scenarios

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	proxymancommand "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
	routercommand "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/common/geodata"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessencoding "github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

const (
	routingTestUser          = "client-42"
	routingTestRUDomain      = "ru.route.test"
	routingTestDefaultDomain = "default.route.test"
	routingTestTargetPort    = xnet.Port(443)
)

func TestVlessMuxUserDestinationRouting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain sockets are required")
	}

	firstRouteStarted := make(chan struct{})
	releaseFirstRoute := make(chan struct{})
	var startFirstRoute sync.Once
	var releaseFirstRouteOnce sync.Once
	releaseFirst := func() {
		releaseFirstRouteOnce.Do(func() {
			close(releaseFirstRoute)
		})
	}

	ruBackend := tcp.Server{
		MsgProcessor: func(msg []byte) []byte {
			startFirstRoute.Do(func() {
				close(firstRouteStarted)
			})
			<-releaseFirstRoute
			return responseWithMarker('R', msg)
		},
	}
	ruDestination, err := ruBackend.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer ruBackend.Close()

	defaultBackend := tcp.Server{
		MsgProcessor: func(msg []byte) []byte {
			return responseWithMarker('D', msg)
		},
	}
	defaultDestination, err := defaultBackend.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer defaultBackend.Close()

	canonicalUUID := uuid.New()
	canonicalUUID[6] = 0
	canonicalUUID[7] = 0
	attemptedUUID := canonicalUUID
	attemptedUUID[6] = 0x12
	attemptedUUID[7] = 0x34
	canonicalUserID := protocol.NewID(canonicalUUID)
	attemptedUserID := protocol.NewID(attemptedUUID)
	socketDir, err := os.MkdirTemp("/tmp", "xray-routing-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	notificationSocket := filepath.Join(socketDir, "notifications.sock")
	controlSocket := filepath.Join(socketDir, "control.sock")

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Error,
				ErrorLogType:  log.LogType_Console,
			}),
			serial.ToTypedMessage(&router.Config{
				DomainStrategy: router.Config_AsIs,
			}),
			serial.ToTypedMessage(&commander.Config{
				Tag:    "api",
				Listen: controlSocket + ",0600",
				Service: []*serial.TypedMessage{
					serial.ToTypedMessage(&proxymancommand.Config{}),
					serial.ToTypedMessage(&routercommand.Config{}),
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "vless-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(serverPort)}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Notifications: notificationSocket,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag:           "deny",
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
			{
				Tag:           "ru-system",
				ProxySettings: serial.ToTypedMessage(freedomTo(ruDestination)),
			},
			{
				Tag:           "default-system",
				ProxySettings: serial.ToTypedMessage(freedomTo(defaultDestination)),
			},
		},
	}

	proxy := newCountingTCPProxy(t, xnet.TCPDestination(xnet.LocalHostIP, serverPort))
	defer proxy.Close()

	ruClientPort := tcp.PickPort()
	defaultClientPort := tcp.PickPort()
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Error,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			dokodemoInbound("ru-client-in", ruClientPort, routingTestRUDomain),
			dokodemoInbound("default-client-in", defaultClientPort, routingTestDefaultDomain),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "vless-mux",
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					MultiplexSettings: &proxyman.MultiplexingConfig{
						Enabled:     true,
						Concurrency: 2,
					},
				}),
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(proxy.Port()),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: attemptedUserID.String(),
							}),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	assertUnixSocketMode(t, notificationSocket, 0o600)
	assertUnixSocketMode(t, controlSocket, 0o600)

	notificationConn, err := dialUnixSocket(notificationSocket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer notificationConn.Close()

	controlConn, err := dialGRPCUnixSocket(controlSocket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer controlConn.Close()

	authResult := make(chan authDaemonResult, 1)
	go emulateAuthDaemon(
		notificationConn,
		proxymancommand.NewHandlerServiceClient(controlConn),
		routercommand.NewRoutingServiceClient(controlConn),
		attemptedUserID.String(),
		canonicalUserID.String(),
		authResult,
	)

	var provisioned authDaemonResult
	authDeadline := time.NewTimer(10 * time.Second)
	defer authDeadline.Stop()
	for {
		if err := attemptUnknownVLESS(proxy.Port(), attemptedUserID); err != nil {
			t.Fatal(err)
		}

		select {
		case provisioned = <-authResult:
			if provisioned.err != nil {
				t.Fatal(provisioned.err)
			}
			goto userProvisioned
		case <-authDeadline.C:
			t.Fatal("auth daemon did not receive the unknown-user notification")
		case <-time.After(25 * time.Millisecond):
		}
	}

userProvisioned:
	if provisioned.attempt.GetAttemptedUuid() != attemptedUserID.String() {
		t.Fatalf(
			"notified UUID = %q, want %q",
			provisioned.attempt.GetAttemptedUuid(),
			attemptedUserID.String(),
		)
	}
	if provisioned.attempt.GetRemoteIp() == "" ||
		provisioned.attempt.GetRemotePort() == 0 ||
		provisioned.attempt.GetTimestamp() == 0 {
		t.Fatalf("incomplete unknown-user notification: %+v", provisioned.attempt)
	}

	handlerClient := proxymancommand.NewHandlerServiceClient(controlConn)
	usersCtx, cancelUsers := context.WithTimeout(context.Background(), 5*time.Second)
	users, err := handlerClient.GetInboundUsers(usersCtx, &proxymancommand.GetInboundUserRequest{
		Tag:   "vless-in",
		Email: routingTestUser,
	})
	cancelUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users.GetUsers()) != 1 || users.GetUsers()[0].GetEmail() != routingTestUser {
		t.Fatalf("dynamic VLESS users = %+v, want %q", users.GetUsers(), routingTestUser)
	}

	failedAuthConnections := proxy.AcceptCount()
	if failedAuthConnections == 0 {
		t.Fatal("unknown UUID did not open a physical VLESS connection")
	}

	defer releaseFirst()
	firstRouteResult := make(chan error, 1)
	go func() {
		firstRouteResult <- exchangeRoute(ruClientPort, []byte("ru-route"), 'R')
	}()

	select {
	case <-firstRouteStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("first logical mux stream did not reach the ru backend")
	}

	if err := exchangeRoute(defaultClientPort, []byte("default-route"), 'D'); err != nil {
		t.Fatal(err)
	}

	releaseFirst()
	select {
	case err := <-firstRouteResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first logical mux stream did not finish")
	}

	if got, want := proxy.AcceptCount(), failedAuthConnections+1; got != want {
		t.Fatalf(
			"post-auth physical VLESS connections through mux = %d, want one new connection after %d failed auth connections",
			got-failedAuthConnections,
			failedAuthConnections,
		)
	}
}

func routingRule(user, domain, outboundTag, ruleTag string) *router.RoutingRule {
	rule := &router.RoutingRule{
		TargetTag: &router.RoutingRule_Tag{
			Tag: outboundTag,
		},
		RuleTag:    ruleTag,
		InboundTag: []string{"vless-in"},
		UserEmail:  []string{user},
	}
	if domain != "" {
		rule.Domain = []*geodata.DomainRule{
			{
				Value: &geodata.DomainRule_Custom{
					Custom: &geodata.Domain{
						Type:  geodata.Domain_Full,
						Value: domain,
					},
				},
			},
		}
	}
	return rule
}

type authDaemonResult struct {
	attempt *inbound.UnknownUserAttempt
	err     error
}

func emulateAuthDaemon(
	notificationConn stdnet.Conn,
	handlerClient proxymancommand.HandlerServiceClient,
	routingClient routercommand.RoutingServiceClient,
	attemptedUUID string,
	canonicalUUID string,
	result chan<- authDaemonResult,
) {
	attempt, err := readUnknownUserAttempt(notificationConn)
	if err != nil {
		result <- authDaemonResult{err: err}
		return
	}
	if attempt.GetAttemptedUuid() != attemptedUUID {
		result <- authDaemonResult{
			attempt: attempt,
			err: fmt.Errorf(
				"auth backend lookup UUID = %q, want %q",
				attempt.GetAttemptedUuid(),
				attemptedUUID,
			),
		}
		return
	}
	attemptedID, err := uuid.ParseString(attempt.GetAttemptedUuid())
	if err != nil {
		result <- authDaemonResult{attempt: attempt, err: fmt.Errorf("parsing attempted UUID: %w", err)}
		return
	}
	canonicalID, err := uuid.ParseString(canonicalUUID)
	if err != nil {
		result <- authDaemonResult{attempt: attempt, err: fmt.Errorf("parsing canonical UUID: %w", err)}
		return
	}
	if vless.ProcessUUID(attemptedID) != vless.ProcessUUID(canonicalID) {
		result <- authDaemonResult{
			attempt: attempt,
			err:     fmt.Errorf("attempted UUID does not map to the canonical credential"),
		}
		return
	}

	getCtx, cancelGet := context.WithTimeout(context.Background(), 5*time.Second)
	current, err := routingClient.GetRuleSet(getCtx, &routercommand.GetRuleSetRequest{})
	cancelGet()
	if err != nil {
		result <- authDaemonResult{attempt: attempt, err: fmt.Errorf("getting route state: %w", err)}
		return
	}

	routeConfig := &router.Config{
		DomainStrategy: router.Config_AsIs,
		Rule: []*router.RoutingRule{
			routingRule(
				routingTestUser,
				routingTestRUDomain,
				"ru-system",
				"client-42-ru",
			),
			routingRule(
				routingTestUser,
				"",
				"default-system",
				"client-42-default",
			),
		},
	}
	replaceCtx, cancelReplace := context.WithTimeout(context.Background(), 5*time.Second)
	replaced, err := routingClient.ReplaceRuleSet(
		replaceCtx,
		&routercommand.ReplaceRuleSetRequest{
			ExpectedVersion: current.GetVersion(),
			Config:          serial.ToTypedMessage(routeConfig),
		},
	)
	cancelReplace()
	if err != nil {
		result <- authDaemonResult{attempt: attempt, err: fmt.Errorf("replacing route state: %w", err)}
		return
	}
	if replaced.GetVersion().GetInstanceId() != current.GetVersion().GetInstanceId() ||
		replaced.GetVersion().GetGeneration() != current.GetVersion().GetGeneration()+1 {
		result <- authDaemonResult{
			attempt: attempt,
			err: fmt.Errorf(
				"route version changed from %+v to %+v",
				current.GetVersion(),
				replaced.GetVersion(),
			),
		}
		return
	}

	addCtx, cancelAdd := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = handlerClient.AlterInbound(addCtx, &proxymancommand.AlterInboundRequest{
		Tag: "vless-in",
		Operation: serial.ToTypedMessage(&proxymancommand.AddUserOperation{
			User: &protocol.User{
				Email: routingTestUser,
				Account: serial.ToTypedMessage(&vless.Account{
					Id: canonicalUUID,
				}),
			},
		}),
	})
	cancelAdd()
	if err != nil {
		result <- authDaemonResult{attempt: attempt, err: fmt.Errorf("adding VLESS user: %w", err)}
		return
	}

	result <- authDaemonResult{attempt: attempt}
}

func readUnknownUserAttempt(conn stdnet.Conn) (*inbound.UnknownUserAttempt, error) {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, fmt.Errorf("setting notification deadline: %w", err)
	}

	var sizeBytes [4]byte
	if _, err := io.ReadFull(conn, sizeBytes[:]); err != nil {
		return nil, fmt.Errorf("reading notification size: %w", err)
	}
	size := binary.BigEndian.Uint32(sizeBytes[:])
	const maxNotificationSize = 64 * 1024
	if size == 0 || size > maxNotificationSize {
		return nil, fmt.Errorf("invalid notification size %d", size)
	}

	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("reading notification body: %w", err)
	}
	attempt := new(inbound.UnknownUserAttempt)
	if err := proto.Unmarshal(body, attempt); err != nil {
		return nil, fmt.Errorf("decoding unknown-user notification: %w", err)
	}
	return attempt, nil
}

func dialUnixSocket(path string, timeout time.Duration) (stdnet.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		connection, err := stdnet.DialTimeout("unix", path, 250*time.Millisecond)
		if err == nil {
			return connection, nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	return nil, fmt.Errorf("dialing Unix socket %q: %w", path, lastErr)
}

func dialGRPCUnixSocket(path string, timeout time.Duration) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return grpc.DialContext(
		ctx,
		"passthrough:///xray-control",
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (stdnet.Conn, error) {
			var dialer stdnet.Dialer
			return dialer.DialContext(ctx, "unix", path)
		}),
	)
}

func assertUnixSocketMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat Unix socket %q: %v", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%q is not a Unix socket: %v", path, info.Mode())
	}
	if got := info.Mode().Perm(); got != expected {
		t.Fatalf("Unix socket %q mode = %04o, want %04o", path, got, expected)
	}
}

func attemptUnknownVLESS(port xnet.Port, id *protocol.ID) error {
	address := stdnet.JoinHostPort("127.0.0.1", port.String())
	connection, err := stdnet.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return fmt.Errorf("dialing VLESS auth attempt: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return fmt.Errorf("setting VLESS auth deadline: %w", err)
	}

	account, err := (&vless.Account{Id: id.String()}).AsAccount()
	if err != nil {
		return fmt.Errorf("building VLESS auth account: %w", err)
	}
	request := &protocol.RequestHeader{
		Version: vlessencoding.Version,
		User: &protocol.MemoryUser{
			Account: account,
		},
		Command: protocol.RequestCommandTCP,
		Address: xnet.DomainAddress(routingTestRUDomain),
		Port:    routingTestTargetPort,
	}
	if err := vlessencoding.EncodeRequestHeader(
		connection,
		request,
		&vlessencoding.Addons{},
	); err != nil {
		return fmt.Errorf("writing VLESS auth attempt: %w", err)
	}

	var response [1]byte
	if _, err := connection.Read(response[:]); err == nil {
		return fmt.Errorf("unknown VLESS user received a response")
	}
	return nil
}

func freedomTo(destination xnet.Destination) *freedom.Config {
	return &freedom.Config{
		DestinationOverride: &freedom.DestinationOverride{
			Server: &protocol.ServerEndpoint{
				Address: xnet.NewIPOrDomain(destination.Address),
				Port:    uint32(destination.Port),
			},
		},
		FinalRules: []*freedom.FinalRuleConfig{
			{Action: freedom.RuleAction_Allow},
		},
	}
}

func dokodemoInbound(tag string, port xnet.Port, domain string) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		Tag: tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}},
			Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
		}),
		ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
			RewriteAddress:  xnet.NewIPOrDomain(xnet.DomainAddress(domain)),
			RewritePort:     uint32(routingTestTargetPort),
			AllowedNetworks: []xnet.Network{xnet.Network_TCP},
		}),
	}
}

func responseWithMarker(marker byte, msg []byte) []byte {
	response := append([]byte(nil), msg...)
	if len(response) > 0 {
		response[0] = marker
	}
	return response
}

func exchangeRoute(port xnet.Port, payload []byte, marker byte) error {
	return exchangeRouteWithTimeout(port, payload, marker, 10*time.Second)
}

func exchangeRouteWithTimeout(
	port xnet.Port,
	payload []byte,
	marker byte,
	timeout time.Duration,
) error {
	address := stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	connection, err := stdnet.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dialing route %q: %w", address, err)
	}
	defer connection.Close()

	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("setting route deadline: %w", err)
	}
	if _, err := connection.Write(payload); err != nil {
		return fmt.Errorf("writing route payload: %w", err)
	}

	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		return fmt.Errorf("reading route response: %w", err)
	}
	expected := responseWithMarker(marker, payload)
	if !bytes.Equal(response, expected) {
		return fmt.Errorf("route response = %q, want %q", response, expected)
	}
	return nil
}

type countingTCPProxy struct {
	listener    stdnet.Listener
	target      string
	acceptCount atomic.Int32

	mu          sync.Mutex
	isClosed    bool
	connections map[stdnet.Conn]struct{}
	acceptDone  chan struct{}
	handlers    sync.WaitGroup
	closeOnce   sync.Once
}

func newCountingTCPProxy(t *testing.T, destination xnet.Destination) *countingTCPProxy {
	t.Helper()

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting counting TCP proxy: %v", err)
	}
	proxy := &countingTCPProxy{
		listener: listener,
		target: stdnet.JoinHostPort(
			destination.Address.String(),
			strconv.Itoa(int(destination.Port)),
		),
		connections: make(map[stdnet.Conn]struct{}),
		acceptDone:  make(chan struct{}),
	}
	go proxy.accept()
	return proxy
}

func (p *countingTCPProxy) Port() xnet.Port {
	return xnet.Port(p.listener.Addr().(*stdnet.TCPAddr).Port)
}

func (p *countingTCPProxy) AcceptCount() int32 {
	return p.acceptCount.Load()
}

func (p *countingTCPProxy) Close() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.isClosed = true
		connections := make([]stdnet.Conn, 0, len(p.connections))
		for connection := range p.connections {
			connections = append(connections, connection)
		}
		p.mu.Unlock()

		_ = p.listener.Close()
		for _, connection := range connections {
			_ = connection.Close()
		}

		<-p.acceptDone
		p.handlers.Wait()
	})
}

func (p *countingTCPProxy) accept() {
	defer close(p.acceptDone)

	for {
		connection, err := p.listener.Accept()
		if err != nil {
			return
		}
		if !p.register(connection) {
			continue
		}

		p.acceptCount.Add(1)
		p.handlers.Add(1)
		go p.forward(connection)
	}
}

func (p *countingTCPProxy) forward(downstream stdnet.Conn) {
	defer p.handlers.Done()
	defer p.unregister(downstream)

	upstream, err := stdnet.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		_ = downstream.Close()
		return
	}
	if !p.register(upstream) {
		_ = downstream.Close()
		return
	}
	defer p.unregister(upstream)

	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		_, _ = io.Copy(upstream, downstream)
		closeWrite(upstream)
	}()
	go func() {
		defer copies.Done()
		_, _ = io.Copy(downstream, upstream)
		closeWrite(downstream)
	}()
	copies.Wait()
}

func (p *countingTCPProxy) register(connection stdnet.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isClosed {
		_ = connection.Close()
		return false
	}
	p.connections[connection] = struct{}{}
	return true
}

func (p *countingTCPProxy) unregister(connection stdnet.Conn) {
	p.mu.Lock()
	delete(p.connections, connection)
	p.mu.Unlock()
	_ = connection.Close()
}

func closeWrite(connection stdnet.Conn) {
	if tcpConnection, ok := connection.(*stdnet.TCPConn); ok {
		_ = tcpConnection.CloseWrite()
	}
}
