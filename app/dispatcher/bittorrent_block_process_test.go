//go:build integration

package dispatcher

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const btBlockedObservationWindow = 1500 * time.Millisecond

// TestBitTorrentBlockProcessE2E proves on a real Xray process that a routing
// rule protocol ["bittorrent"] -> block drops torrent traffic while ordinary
// UDP and TCP flows pass through the same proxy:
//
//   - uTP, DHT and UDP tracker datagrams sent through SOCKS never reach the
//     destination and never produce a reply;
//   - ordinary and padded EDNS queries and a plain datagram sent the same way
//     are answered;
//   - a TCP BitTorrent handshake is cut by the proxy while a plain TCP
//     exchange is echoed.
//
// The pass-through controls guard against a vacuous pass: if the proxy
// dropped everything, the blocked cases would "pass" for the wrong reason.
func TestBitTorrentBlockProcessE2E(t *testing.T) {
	workDir := t.TempDir()
	xrayBin := btBuildXray(t, workDir)

	udpEcho := btNewUDPResponder(t)
	t.Cleanup(func() { _ = udpEcho.conn.Close() })
	tcpEcho := btNewTCPResponder(t)
	t.Cleanup(func() { _ = tcpEcho.listener.Close() })

	socksPort := btFreeTCPPort(t)
	process := btStartXray(t, xrayBin, btXrayConfig(socksPort), filepath.Join(workDir, "config.json"))
	t.Cleanup(func() {
		// Parent cleanup runs after every subtest. A failed subtest marks the
		// parent failed too, so this makes the same captured Xray logs available
		// for every control and block assertion without threading process through
		// each helper.
		if t.Failed() {
			t.Logf("Xray logs:\n%s", process.btLogs())
		}
	})
	btWaitSOCKS(t, process, socksPort)

	// Controls first: if pass-through is broken the blocked assertions
	// below would be meaningless.
	t.Run("dns query through proxy is answered", func(t *testing.T) {
		query := btDNSQuery(0xBEEF)
		response := btRoundTripUDP(t, socksPort, udpEcho.addr, query, 5*time.Second)
		if len(response) < 3 || binary.BigEndian.Uint16(response[0:2]) != 0xBEEF || response[2]&0x80 == 0 {
			t.Fatalf("unexpected DNS response: % x", response)
		}
	})

	t.Run("padded edns dns query through proxy is answered", func(t *testing.T) {
		query := btPaddedEDNSQuery(0xCAFE)
		if len(query) != 98 {
			t.Fatalf("padded EDNS query length = %d, want 98", len(query))
		}
		response := btRoundTripUDP(t, socksPort, udpEcho.addr, query, 5*time.Second)
		if len(response) < 3 || binary.BigEndian.Uint16(response[0:2]) != 0xCAFE || response[2]&0x80 == 0 {
			t.Fatalf("unexpected padded EDNS response: % x", response)
		}
	})

	t.Run("plain udp datagram through proxy is echoed", func(t *testing.T) {
		payload := []byte("plain-udp-control")
		response := btRoundTripUDP(t, socksPort, udpEcho.addr, payload, 5*time.Second)
		if !bytes.Equal(response, payload) {
			t.Fatalf("echo mismatch: got %q", response)
		}
	})

	t.Run("plain tcp exchange through proxy is echoed", func(t *testing.T) {
		payload := []byte("plain-tcp-control")
		response := btRoundTripTCP(t, socksPort, tcpEcho.addr.Port, payload, 5*time.Second)
		if !bytes.Equal(response, payload) {
			t.Fatalf("echo mismatch: got %q", response)
		}
	})

	// Torrent traffic must be dropped by the protocol rule. Each probe is
	// answered only if it leaks: the responder echoes everything it gets.
	t.Run("utp data packet is blocked", func(t *testing.T) {
		payload := btUTPDataPacket()
		btAssertBlockedUDP(t, socksPort, udpEcho, payload, "uTP")
	})

	t.Run("dht get_peers query is blocked", func(t *testing.T) {
		payload := btDHTGetPeersQuery()
		btAssertBlockedUDP(t, socksPort, udpEcho, payload, "DHT")
	})

	t.Run("udp tracker connect is blocked", func(t *testing.T) {
		payload := btUDPTrackerConnect()
		btAssertBlockedUDP(t, socksPort, udpEcho, payload, "UDP tracker")
	})

	t.Run("tcp bittorrent handshake is blocked", func(t *testing.T) {
		handshake := btPeerHandshake()
		conn := btSOCKSConnect(t, socksPort, tcpEcho.addr.Port)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(btBlockedObservationWindow))
		if _, err := conn.Write(handshake); err != nil {
			t.Fatalf("write handshake: %v", err)
		}
		buffer := make([]byte, len(handshake))
		if n, err := conn.Read(buffer); n > 0 || err == nil {
			t.Fatalf("proxy returned %d bytes for a bittorrent handshake: %v", n, err)
		}
		if tcpEcho.btWaitForRecorded(handshake, btBlockedObservationWindow) {
			t.Fatalf("bittorrent handshake reached the destination")
		}
	})
}

// btAssertBlockedUDP sends payload through the proxy and proves two things
// within a bounded window: no reply comes back, and the destination never
// received the payload.
func btAssertBlockedUDP(t *testing.T, socksPort int, echo *btUDPResponder, payload []byte, kind string) {
	t.Helper()
	relay := btUDPAssociate(t, socksPort)
	defer relay.conn.Close()

	datagram := btSOCKSUDPDatagram(echo.addr.IP, echo.addr.Port, payload)
	if _, err := relay.conn.WriteTo(datagram, relay.addr); err != nil {
		t.Fatalf("send %s datagram: %v", kind, err)
	}
	_ = relay.conn.SetReadDeadline(time.Now().Add(btBlockedObservationWindow))
	buffer := make([]byte, 2048)
	n, _, err := relay.conn.ReadFromUDP(buffer)
	if err == nil {
		t.Fatalf("%s datagram was not blocked, got %d-byte reply: % x", kind, n, buffer[:n])
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("wait for blocked %s datagram: %v", kind, err)
	}
	if echo.btRecorded(payload) {
		t.Fatalf("%s payload reached the destination", kind)
	}
}

func btRoundTripUDP(t *testing.T, socksPort int, dest *net.UDPAddr, payload []byte, timeout time.Duration) []byte {
	t.Helper()
	relay := btUDPAssociate(t, socksPort)
	defer relay.conn.Close()

	if _, err := relay.conn.WriteTo(btSOCKSUDPDatagram(dest.IP, dest.Port, payload), relay.addr); err != nil {
		t.Fatalf("send udp payload: %v", err)
	}
	_ = relay.conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 2048)
	n, _, err := relay.conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("udp round trip: %v", err)
	}
	response, err := btParseSOCKSUDP(buffer[:n])
	if err != nil {
		t.Fatalf("parse udp reply: %v", err)
	}
	return response
}

func btRoundTripTCP(t *testing.T, socksPort, port int, payload []byte, timeout time.Duration) []byte {
	t.Helper()
	conn := btSOCKSConnect(t, socksPort, port)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write tcp payload: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := btReadFull(conn, response); err != nil {
		t.Fatalf("tcp round trip: %v", err)
	}
	return response
}

type btProcess struct {
	command *exec.Cmd
	done    chan struct{}

	waitMu  sync.Mutex
	waitErr error
	logs    btLockedBuffer
}

func (p *btProcess) btLogs() string {
	return p.logs.btString()
}

func (p *btProcess) btWaitErr() error {
	p.waitMu.Lock()
	defer p.waitMu.Unlock()
	return p.waitErr
}

type btLockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *btLockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *btLockedBuffer) btString() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func btBuildXray(t *testing.T, workDir string) string {
	t.Helper()
	if existing := os.Getenv("XRAY_E2E_BIN"); existing != "" {
		return existing
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(workDir, "xray")
	command := exec.Command("go", "build", "-o", output, "./main")
	command.Dir = root
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build xray: %v\n%s", err, combined)
	}
	return output
}

func btStartXray(t *testing.T, binary, config, configPath string) *btProcess {
	t.Helper()
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	process := &btProcess{command: exec.Command(binary, "run", "-c", configPath), done: make(chan struct{})}
	process.command.Stdout = &process.logs
	process.command.Stderr = &process.logs
	if err := process.command.Start(); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	go func() {
		process.waitMu.Lock()
		process.waitErr = process.command.Wait()
		process.waitMu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		_ = process.command.Process.Kill()
		<-process.done
	})
	return process
}

// btXrayConfig runs SOCKS with sniffing enabled and a single routing rule
// that sends sniffed bittorrent traffic to the blackhole.
func btXrayConfig(socksPort int) string {
	return fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "socks",
			"settings": {"udp": true},
			"sniffing": {"enabled": true}
		}],
		"outbounds": [
			{"tag": "direct", "protocol": "freedom"},
			{"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "none"}}}
		],
		"routing": {"rules": [
			{"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"}
		]}
	}`, socksPort)
}

func btWaitSOCKS(t *testing.T, process *btProcess, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
			err := btSOCKSGreeting(conn)
			_ = conn.Close()
			if err == nil {
				return
			}
		}
		select {
		case <-process.done:
			t.Fatalf("process exited before SOCKS readiness on %s: %v\n%s", address, process.btWaitErr(), process.btLogs())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("SOCKS endpoint did not become ready on %s\n%s", address, process.btLogs())
}

// --- destination responders ---

type btUDPResponder struct {
	conn *net.UDPConn
	addr *net.UDPAddr

	mu       sync.Mutex
	received [][]byte
}

func (r *btUDPResponder) btRecorded(payload []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range r.received {
		if bytes.Equal(item, payload) {
			return true
		}
	}
	return false
}

func btNewUDPResponder(t *testing.T) *btUDPResponder {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	responder := &btUDPResponder{conn: conn, addr: conn.LocalAddr().(*net.UDPAddr)}
	go func() {
		buffer := make([]byte, 65536)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			payload := bytes.Clone(buffer[:n])
			responder.mu.Lock()
			responder.received = append(responder.received, payload)
			responder.mu.Unlock()
			var reply []byte
			if n >= 12 && payload[2]&0xFE == 0 { // standard query flags (at most RD set)
				reply = btDNSResponse(payload)
			} else {
				reply = payload
			}
			_, _ = conn.WriteToUDP(reply, source)
		}
	}()
	return responder
}

// btDNSResponse answers a query with its transaction id and the QR bit set.
func btDNSResponse(query []byte) []byte {
	reply := make([]byte, 0, len(query)+16)
	reply = append(reply, query[0], query[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0)
	reply = append(reply, query[12:]...)
	return reply
}

func btDNSQuery(txn uint16) []byte {
	query := []byte{byte(txn >> 8), byte(txn), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"proxy", "example", "test"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

func btPaddedEDNSQuery(txn uint16) []byte {
	query := btDNSQuery(txn)
	binary.BigEndian.PutUint16(query[10:12], 1)
	query = append(query,
		0, 0, 0x29, 0x10, 0, 0, 0x80, 0, 0, 0, 0x33,
		0, 2, 0, 0x2f,
	)
	query = append(query, make([]byte, 45)...)
	return append(query, 0x12, 0x34)
}

type btTCPResponder struct {
	listener *net.TCPListener
	addr     *net.TCPAddr

	mu       sync.Mutex
	received [][]byte // One accumulated byte stream per accepted connection.
}

func (r *btTCPResponder) btRecord(connection int, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received[connection] = append(r.received[connection], payload...)
}

func (r *btTCPResponder) btWaitForRecorded(payload []byte, window time.Duration) bool {
	deadline := time.Now().Add(window)
	for {
		r.mu.Lock()
		for _, item := range r.received {
			if bytes.Contains(item, payload) {
				r.mu.Unlock()
				return true
			}
		}
		r.mu.Unlock()
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func btNewTCPResponder(t *testing.T) *btTCPResponder {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	responder := &btTCPResponder{listener: listener, addr: listener.Addr().(*net.TCPAddr)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			responder.mu.Lock()
			connection := len(responder.received)
			responder.received = append(responder.received, nil)
			responder.mu.Unlock()
			go func(conn net.Conn) {
				defer conn.Close()
				buffer := make([]byte, 4096)
				for {
					n, err := conn.Read(buffer)
					if n > 0 {
						responder.btRecord(connection, buffer[:n])
						_, _ = conn.Write(buffer[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return responder
}

// --- minimal SOCKS5 client ---

func btSOCKSGreeting(conn net.Conn) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := btReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("socks greeting reply: % x", reply)
	}
	return nil
}

func btSOCKSRequest(conn net.Conn, command byte, port int) error {
	request := []byte{0x05, command, 0x00, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if _, err := conn.Write(request); err != nil {
		return err
	}
	reply := make([]byte, 10)
	if _, err := btReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks reply status %d", reply[1])
	}
	return nil
}

func btSOCKSConnect(t *testing.T, socksPort, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := btSOCKSGreeting(conn); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if err := btSOCKSRequest(conn, 0x01, port); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return conn
}

type btUDPRelay struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func btUDPAssociate(t *testing.T, socksPort int) *btUDPRelay {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := btSOCKSGreeting(conn); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("udp associate request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := btReadFull(conn, reply); err != nil {
		t.Fatalf("udp associate reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("udp associate status %d", reply[1])
	}
	relayAddr := &net.UDPAddr{IP: net.IPv4(reply[4], reply[5], reply[6], reply[7]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return &btUDPRelay{conn: socket, addr: relayAddr}
}

func btSOCKSUDPDatagram(ip net.IP, port int, payload []byte) []byte {
	datagram := []byte{0x00, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	return append(datagram, payload...)
}

func btParseSOCKSUDP(datagram []byte) ([]byte, error) {
	if len(datagram) < 10 || datagram[3] != 0x01 {
		return nil, fmt.Errorf("unexpected udp header: % x", datagram[:min(10, len(datagram))])
	}
	return datagram[10:], nil
}

func btReadFull(conn net.Conn, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		n, err := conn.Read(buffer[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// --- torrent payloads (same wire shapes as the corpus tests) ---

func btUTPDataPacket() []byte {
	packet := make([]byte, 20, 520)
	packet[0] = 0x01 // ST_DATA, version 1
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[2:4], 0x07E1)
	binary.BigEndian.PutUint32(packet[4:8], 0xD5396E1C)
	binary.BigEndian.PutUint32(packet[8:12], 900)
	binary.BigEndian.PutUint32(packet[12:16], 0x100000)
	binary.BigEndian.PutUint16(packet[16:18], 101)
	binary.BigEndian.PutUint16(packet[18:20], 100)
	for i := len(packet); i < 520; i++ {
		packet = append(packet, byte(i%251))
	}
	return packet
}

func btDHTGetPeersQuery() []byte {
	nodeID := make([]byte, 20)
	info, _ := hex.DecodeString("dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c")
	query := "d1:ad2:id20:" + string(nodeID) + "9:info_hash20:" + string(info) + "e1:q9:get_peers1:t2:aa1:y1:qe"
	return []byte(query)
}

func btUDPTrackerConnect() []byte {
	request := make([]byte, 16)
	binary.BigEndian.PutUint32(request[0:4], 0x417)
	binary.BigEndian.PutUint32(request[4:8], 0x27101980)
	binary.BigEndian.PutUint32(request[12:16], 0xDEADBEEF)
	return request
}

func btPeerHandshake() []byte {
	handshake := make([]byte, 0, 68)
	handshake = append(handshake, 19)
	handshake = append(handshake, "BitTorrent protocol"...)
	handshake = append(handshake, 0, 0, 0, 0, 0, 0x10, 0, 0x05)
	info, _ := hex.DecodeString("dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c")
	handshake = append(handshake, info...)
	return append(handshake, "-qB4530-xk2f9amqbtt3"...)
}

func btFreeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}
