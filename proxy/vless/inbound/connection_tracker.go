package inbound

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/vless"
)

var (
	errConnectionTrackerClosed = errors.New("connection tracker is closed")
	errInvalidConnectionSource = errors.New("connection source is not an ip address")
)

type resettableConnection interface {
	SetLinger(int) error
	Close() error
}

type connectionTracker struct {
	mu               sync.Mutex
	users            map[[16]byte]*activeConnections
	nextGeneration   uint64
	nextConnectionID uint64
	isClosed         bool
}

type activeConnections struct {
	ip          netip.Addr
	generation  uint64
	connections map[uint64]resettableConnection
}

func newConnectionTracker() *connectionTracker {
	return &connectionTracker{
		users: make(map[[16]byte]*activeConnections),
	}
}

func normalizeSourceIP(address net.Address) (netip.Addr, bool) {
	if address == nil || !address.Family().IsIP() {
		return netip.Addr{}, false
	}

	ip, ok := netip.AddrFromSlice(address.IP())
	if !ok {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func (h *Handler) registerAuthenticatedConnection(
	account *vless.MemoryAccount,
	source net.Address,
	connection resettableConnection,
) (func(), []error, error) {
	ip, ok := normalizeSourceIP(source)
	if !ok {
		return nil, nil, errInvalidConnectionSource
	}

	return h.connectionTracker.register(
		vless.ProcessUUID(account.ID.UUID()),
		ip,
		connection,
	)
}

func (t *connectionTracker) register(
	userID [16]byte,
	ip netip.Addr,
	connection resettableConnection,
) (func(), []error, error) {
	t.mu.Lock()
	if t.isClosed {
		t.mu.Unlock()
		return nil, nil, errConnectionTrackerClosed
	}

	active := t.users[userID]
	evicted := make([]resettableConnection, 0)
	if active == nil || active.ip != ip {
		if active != nil {
			evicted = make([]resettableConnection, 0, len(active.connections))
			for _, oldConnection := range active.connections {
				evicted = append(evicted, oldConnection)
			}
		}

		t.nextGeneration++
		active = &activeConnections{
			ip:          ip,
			generation:  t.nextGeneration,
			connections: make(map[uint64]resettableConnection),
		}
		t.users[userID] = active
	}

	t.nextConnectionID++
	connectionID := t.nextConnectionID
	generation := active.generation
	active.connections[connectionID] = connection
	t.mu.Unlock()

	release := func() {
		t.release(userID, generation, connectionID)
	}
	return release, resetConnections(evicted), nil
}

func (t *connectionTracker) release(userID [16]byte, generation, connectionID uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	active := t.users[userID]
	if active == nil || active.generation != generation {
		return
	}

	delete(active.connections, connectionID)
	if len(active.connections) == 0 {
		delete(t.users, userID)
	}
}

func (t *connectionTracker) close() []error {
	t.mu.Lock()
	if t.isClosed {
		t.mu.Unlock()
		return nil
	}
	t.isClosed = true

	connections := make([]resettableConnection, 0)
	for _, active := range t.users {
		for _, connection := range active.connections {
			connections = append(connections, connection)
		}
	}
	clear(t.users)
	t.mu.Unlock()

	return resetConnections(connections)
}

func resetConnections(connections []resettableConnection) []error {
	resetErrs := make([]error, 0)
	for _, connection := range connections {
		if err := connection.SetLinger(0); err != nil {
			resetErrs = append(resetErrs, fmt.Errorf("setting linger to zero: %w", err))
		}
		if err := connection.Close(); err != nil {
			resetErrs = append(resetErrs, fmt.Errorf("closing connection: %w", err))
		}
	}
	return resetErrs
}
