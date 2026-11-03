package inbound

import (
	"errors"
	stdnet "net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

type testResettableConnection struct {
	mu           sync.Mutex
	lingerValues []int
	closeCount   int
	setLingerErr error
	closeErr     error
	onSetLinger  func()
}

func (c *testResettableConnection) SetLinger(seconds int) error {
	c.mu.Lock()
	c.lingerValues = append(c.lingerValues, seconds)
	onSetLinger := c.onSetLinger
	err := c.setLingerErr
	c.mu.Unlock()

	if onSetLinger != nil {
		onSetLinger()
	}
	return err
}

func (c *testResettableConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCount++
	return c.closeErr
}

func (c *testResettableConnection) resetState() ([]int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	lingerValues := append([]int{}, c.lingerValues...)
	return lingerValues, c.closeCount
}

func TestConnectionTracker_SameIPKeepsConnections(t *testing.T) {
	tracker := newConnectionTracker()
	userID := [16]byte{1}
	ip := netip.MustParseAddr("192.0.2.1")
	first := &testResettableConnection{}
	second := &testResettableConnection{}

	releaseFirst, resetErrs, err := tracker.register(userID, ip, first)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst()
	if len(resetErrs) != 0 {
		t.Fatalf("first registration returned reset errors: %v", resetErrs)
	}

	releaseSecond, resetErrs, err := tracker.register(userID, ip, second)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecond()
	if len(resetErrs) != 0 {
		t.Fatalf("same-ip registration returned reset errors: %v", resetErrs)
	}

	assertNotReset(t, first)
	assertNotReset(t, second)

	if closeErrs := tracker.close(); len(closeErrs) != 0 {
		t.Fatalf("closing tracker: %v", closeErrs)
	}
	assertReset(t, first)
	assertReset(t, second)
}

func TestConnectionTracker_NewIPResetsPreviousConnections(t *testing.T) {
	tracker := newConnectionTracker()
	userID := [16]byte{2}
	oldIP := netip.MustParseAddr("192.0.2.1")
	newIP := netip.MustParseAddr("192.0.2.2")
	oldFirst := &testResettableConnection{}
	oldSecond := &testResettableConnection{}
	current := &testResettableConnection{}

	releaseOldFirst := mustRegister(t, tracker, userID, oldIP, oldFirst)
	defer releaseOldFirst()
	releaseOldSecond := mustRegister(t, tracker, userID, oldIP, oldSecond)
	defer releaseOldSecond()
	releaseCurrent := mustRegister(t, tracker, userID, newIP, current)
	defer releaseCurrent()

	assertReset(t, oldFirst)
	assertReset(t, oldSecond)
	assertNotReset(t, current)
}

func TestConnectionTracker_DifferentUUIDIsUnaffected(t *testing.T) {
	tracker := newConnectionTracker()
	firstUser := [16]byte{3}
	secondUser := [16]byte{4}
	oldIP := netip.MustParseAddr("192.0.2.1")
	newIP := netip.MustParseAddr("192.0.2.2")
	firstUserOld := &testResettableConnection{}
	firstUserCurrent := &testResettableConnection{}
	secondUserConnection := &testResettableConnection{}

	defer mustRegister(t, tracker, firstUser, oldIP, firstUserOld)()
	defer mustRegister(t, tracker, secondUser, oldIP, secondUserConnection)()
	defer mustRegister(t, tracker, firstUser, newIP, firstUserCurrent)()

	assertReset(t, firstUserOld)
	assertNotReset(t, firstUserCurrent)
	assertNotReset(t, secondUserConnection)
}

func TestConnectionTracker_StaleReleaseCannotRemoveCurrentGeneration(t *testing.T) {
	tracker := newConnectionTracker()
	userID := [16]byte{5}
	oldIP := netip.MustParseAddr("192.0.2.1")
	currentIP := netip.MustParseAddr("192.0.2.2")
	old := &testResettableConnection{}
	currentFirst := &testResettableConnection{}
	currentSecond := &testResettableConnection{}

	releaseOld := mustRegister(t, tracker, userID, oldIP, old)
	releaseCurrentFirst := mustRegister(t, tracker, userID, currentIP, currentFirst)
	releaseOld()
	releaseCurrentSecond := mustRegister(t, tracker, userID, currentIP, currentSecond)

	assertNotReset(t, currentFirst)
	assertNotReset(t, currentSecond)
	if closeErrs := tracker.close(); len(closeErrs) != 0 {
		t.Fatalf("closing tracker: %v", closeErrs)
	}
	assertReset(t, currentFirst)
	assertReset(t, currentSecond)

	releaseCurrentFirst()
	releaseCurrentSecond()
}

func TestConnectionTracker_ResetRunsOutsideMutex(t *testing.T) {
	tracker := newConnectionTracker()
	userID := [16]byte{6}
	oldIP := netip.MustParseAddr("192.0.2.1")
	newIP := netip.MustParseAddr("192.0.2.2")
	old := &testResettableConnection{}
	releaseOld := mustRegister(t, tracker, userID, oldIP, old)
	old.onSetLinger = releaseOld

	done := make(chan error, 1)
	go func() {
		_, resetErrs, err := tracker.register(userID, newIP, &testResettableConnection{})
		if err == nil && len(resetErrs) != 0 {
			err = errors.Join(resetErrs...)
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("registration deadlocked while resetting the previous connection")
	}
	if closeErrs := tracker.close(); len(closeErrs) != 0 {
		t.Fatalf("closing tracker: %v", closeErrs)
	}
}

func TestConnectionTracker_CloseResetsConnectionsAndRejectsRegistration(t *testing.T) {
	tracker := newConnectionTracker()
	userID := [16]byte{7}
	ip := netip.MustParseAddr("192.0.2.1")
	connection := &testResettableConnection{}

	release := mustRegister(t, tracker, userID, ip, connection)
	if closeErrs := tracker.close(); len(closeErrs) != 0 {
		t.Fatalf("closing tracker: %v", closeErrs)
	}
	assertReset(t, connection)
	release()

	releaseAfterClose, resetErrs, err := tracker.register(
		userID,
		ip,
		&testResettableConnection{},
	)
	if !errors.Is(err, errConnectionTrackerClosed) {
		t.Fatalf("registering after close: got %v, want %v", err, errConnectionTrackerClosed)
	}
	if releaseAfterClose != nil {
		t.Fatal("registration after close returned a release function")
	}
	if len(resetErrs) != 0 {
		t.Fatalf("registration after close returned reset errors: %v", resetErrs)
	}
}

func TestConnectionTracker_ResetErrorsDoNotRejectNewConnection(t *testing.T) {
	tracker := newConnectionTracker()
	userID := [16]byte{8}
	oldIP := netip.MustParseAddr("192.0.2.1")
	newIP := netip.MustParseAddr("192.0.2.2")
	old := &testResettableConnection{
		setLingerErr: errors.New("linger failed"),
		closeErr:     errors.New("close failed"),
	}
	current := &testResettableConnection{}

	defer mustRegister(t, tracker, userID, oldIP, old)()
	releaseCurrent, resetErrs, err := tracker.register(userID, newIP, current)
	if err != nil {
		t.Fatalf("registering winner: %v", err)
	}
	defer releaseCurrent()
	if len(resetErrs) != 2 {
		t.Fatalf("reset error count: got %d, want 2", len(resetErrs))
	}
	assertNotReset(t, current)
}

func TestConnectionTracker_ConcurrentDifferentIPsHaveOneWinner(t *testing.T) {
	const iterations = 100
	for range iterations {
		tracker := newConnectionTracker()
		userID := [16]byte{9}
		connections := []*testResettableConnection{{}, {}}
		ips := []netip.Addr{
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("192.0.2.2"),
		}
		start := make(chan struct{})
		type result struct {
			release   func()
			resetErrs []error
			err       error
		}
		results := make(chan result, len(connections))
		releases := make([]func(), 0, len(connections))

		var waitGroup sync.WaitGroup
		for index := range connections {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				<-start
				release, resetErrs, err := tracker.register(
					userID,
					ips[index],
					connections[index],
				)
				results <- result{release: release, resetErrs: resetErrs, err: err}
			}()
		}
		close(start)
		waitGroup.Wait()
		close(results)

		for result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			if len(result.resetErrs) != 0 {
				t.Fatalf("registration returned reset errors: %v", result.resetErrs)
			}
			releases = append(releases, result.release)
		}

		resetCount := 0
		for _, connection := range connections {
			_, closeCount := connection.resetState()
			if closeCount == 1 {
				resetCount++
			}
		}
		if resetCount != 1 {
			t.Fatalf("reset connection count: got %d, want 1", resetCount)
		}
		for _, release := range releases {
			release()
		}
	}
}

func TestNormalizeSourceIP(t *testing.T) {
	tests := []struct {
		name     string
		address  net.Address
		expected netip.Addr
		isValid  bool
	}{
		{
			name:     "ipv4",
			address:  net.IPAddress([]byte{192, 0, 2, 1}),
			expected: netip.MustParseAddr("192.0.2.1"),
			isValid:  true,
		},
		{
			name:     "ipv6",
			address:  net.IPAddress(stdnet.ParseIP("2001:db8::1")),
			expected: netip.MustParseAddr("2001:db8::1"),
			isValid:  true,
		},
		{
			name: "ipv4-mapped ipv6",
			address: testIPAddress{
				ip:     stdnet.ParseIP("::ffff:192.0.2.1"),
				family: net.AddressFamilyIPv6,
			},
			expected: netip.MustParseAddr("192.0.2.1"),
			isValid:  true,
		},
		{
			name:    "domain",
			address: net.DomainAddress("example.com"),
			isValid: false,
		},
		{
			name:    "missing address",
			address: nil,
			isValid: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, ok := normalizeSourceIP(test.address)
			if ok != test.isValid {
				t.Fatalf("validity: got %v, want %v", ok, test.isValid)
			}
			if actual != test.expected {
				t.Fatalf("address: got %v, want %v", actual, test.expected)
			}
		})
	}
}

func TestHandler_RegisterAuthenticatedConnectionUsesCanonicalUUID(t *testing.T) {
	handler := &Handler{connectionTracker: newConnectionTracker()}
	firstUUID := uuid.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	secondUUID := firstUUID
	secondUUID[6] = 99
	secondUUID[7] = 100
	firstAccount := &vless.MemoryAccount{ID: protocol.NewID(firstUUID)}
	secondAccount := &vless.MemoryAccount{ID: protocol.NewID(secondUUID)}
	oldConnection := &testResettableConnection{}
	currentConnection := &testResettableConnection{}

	releaseOld, resetErrs, err := handler.registerAuthenticatedConnection(
		firstAccount,
		net.IPAddress([]byte{192, 0, 2, 1}),
		oldConnection,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(resetErrs) != 0 {
		t.Fatalf("first registration returned reset errors: %v", resetErrs)
	}
	defer releaseOld()

	releaseCurrent, resetErrs, err := handler.registerAuthenticatedConnection(
		secondAccount,
		net.IPAddress([]byte{192, 0, 2, 2}),
		currentConnection,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(resetErrs) != 0 {
		t.Fatalf("second registration returned reset errors: %v", resetErrs)
	}
	defer releaseCurrent()

	assertReset(t, oldConnection)
	assertNotReset(t, currentConnection)
}

type testIPAddress struct {
	ip     stdnet.IP
	family net.AddressFamily
}

func (a testIPAddress) IP() stdnet.IP {
	return a.ip
}

func (testIPAddress) Domain() string {
	return ""
}

func (a testIPAddress) Family() net.AddressFamily {
	return a.family
}

func (a testIPAddress) String() string {
	return a.ip.String()
}

func mustRegister(
	t *testing.T,
	tracker *connectionTracker,
	userID [16]byte,
	ip netip.Addr,
	connection resettableConnection,
) func() {
	t.Helper()
	release, resetErrs, err := tracker.register(userID, ip, connection)
	if err != nil {
		t.Fatal(err)
	}
	if len(resetErrs) != 0 {
		t.Fatalf("registration returned reset errors: %v", resetErrs)
	}
	return release
}

func assertReset(t *testing.T, connection *testResettableConnection) {
	t.Helper()
	lingerValues, closeCount := connection.resetState()
	if len(lingerValues) != 1 || lingerValues[0] != 0 {
		t.Fatalf("linger values: got %v, want [0]", lingerValues)
	}
	if closeCount != 1 {
		t.Fatalf("close count: got %d, want 1", closeCount)
	}
}

func assertNotReset(t *testing.T, connection *testResettableConnection) {
	t.Helper()
	lingerValues, closeCount := connection.resetState()
	if len(lingerValues) != 0 {
		t.Fatalf("linger values: got %v, want none", lingerValues)
	}
	if closeCount != 0 {
		t.Fatalf("close count: got %d, want 0", closeCount)
	}
}
