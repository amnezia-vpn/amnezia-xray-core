package inbound

import (
	"bytes"
	"context"
	"encoding/binary"
	stderrors "errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
	"google.golang.org/protobuf/proto"
)

func TestMarshalUnknownUserNotificationFrame(t *testing.T) {
	now := time.Unix(1_725_000_123, 987_654_321)
	remoteAddr := &net.TCPAddr{
		IP:   net.ParseIP("192.0.2.19"),
		Port: 443,
	}
	attemptedUUID := "01234567-89ab-cdef-0123-456789abcdef"

	frame, err := marshalUnknownUserNotification(remoteAddr, attemptedUUID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) < 4 {
		t.Fatalf("frame is too short: %d", len(frame))
	}
	if got, want := int(binary.BigEndian.Uint32(frame[:4])), len(frame)-4; got != want {
		t.Fatalf("payload length prefix = %d, want %d", got, want)
	}

	var attempt UnknownUserAttempt
	if err := proto.Unmarshal(frame[4:], &attempt); err != nil {
		t.Fatal(err)
	}
	if got, want := attempt.GetRemoteIp(), remoteAddr.IP.String(); got != want {
		t.Errorf("remote IP = %q, want %q", got, want)
	}
	if got, want := attempt.GetRemotePort(), int32(remoteAddr.Port); got != want {
		t.Errorf("remote port = %d, want %d", got, want)
	}
	if got := attempt.GetAttemptedUuid(); got != attemptedUUID {
		t.Errorf("attempted UUID = %q, want %q", got, attemptedUUID)
	}
	if got, want := attempt.GetTimestamp(), now.Unix(); got != want {
		t.Errorf("timestamp = %d, want %d", got, want)
	}
}

func TestUnknownUserNotifierDisabled(t *testing.T) {
	notifier, err := newUnknownUserNotifierWithOptions(
		context.Background(),
		"",
		defaultUnknownUserNotifierOptions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if notifier != nil {
		t.Fatal("disabled notifications allocated notifier state")
	}
}

func TestUnknownUserNotificationDeduplicatorBoundedTTL(t *testing.T) {
	const capacity = 2
	ttl := 30 * time.Second
	now := time.Unix(1_725_000_000, 0)
	dedup := newUnknownUserNotificationDeduplicator(ttl, capacity)

	firstToken, allowed := dedup.Reserve("first", now)
	if !allowed {
		t.Fatal("first reservation was rejected")
	}
	if _, allowed := dedup.Reserve("first", now.Add(time.Second)); allowed {
		t.Fatal("duplicate reservation was accepted before TTL")
	}
	if _, allowed := dedup.Reserve("second", now); !allowed {
		t.Fatal("second key was rejected")
	}
	if _, allowed := dedup.Reserve("third", now); !allowed {
		t.Fatal("third key was rejected")
	}
	if got := dedup.Len(); got != capacity {
		t.Fatalf("dedup size = %d, want %d", got, capacity)
	}

	replacementToken, allowed := dedup.Reserve("first", now)
	if !allowed {
		t.Fatal("capacity eviction did not release oldest key")
	}
	dedup.Forget("first", firstToken)
	if _, allowed := dedup.Reserve("first", now); allowed {
		t.Fatal("stale rollback removed a newer reservation")
	}
	dedup.Forget("first", replacementToken)
	if _, allowed := dedup.Reserve("first", now); !allowed {
		t.Fatal("matching rollback did not release reservation")
	}

	if _, allowed := dedup.Reserve("expired", now.Add(ttl+time.Nanosecond)); !allowed {
		t.Fatal("expired entries were not released")
	}
	if got := dedup.Len(); got > capacity {
		t.Fatalf("dedup size = %d, exceeds capacity %d", got, capacity)
	}
}

func TestUnknownUserNotifierDedupAndTTL(t *testing.T) {
	options := defaultUnknownUserNotifierOptions()
	options.dedupTTL = time.Second
	options.writeTimeout = time.Second

	var clock atomic.Int64
	now := time.Now()
	clock.Store(now.UnixNano())
	options.now = func() time.Time {
		return time.Unix(0, clock.Load())
	}

	socketPath := notificationSocketPath(t)
	notifier, err := newUnknownUserNotifierWithOptions(context.Background(), socketPath, options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := notifier.Close(); err != nil {
			t.Errorf("close notifier: %v", err)
		}
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waitFor(t, time.Second, func() bool {
		return notifier.clientCount.Load() == 1
	})

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 8443}
	attemptedUUID := mustParseUUID(t, "01234567-89ab-cdef-0123-456789abcdef")
	notifier.Notify(context.Background(), remoteAddr, attemptedUUID)

	first := readUnknownUserNotification(t, client, time.Second)
	if got, want := first.GetAttemptedUuid(), attemptedUUID.String(); got != want {
		t.Fatalf("attempted UUID = %q, want %q", got, want)
	}
	if got, want := first.GetRemoteIp(), remoteAddr.IP.String(); got != want {
		t.Fatalf("remote IP = %q, want %q", got, want)
	}
	if got, want := first.GetRemotePort(), int32(remoteAddr.Port); got != want {
		t.Fatalf("remote port = %d, want %d", got, want)
	}

	notifier.Notify(context.Background(), remoteAddr, attemptedUUID)
	expectNoNotification(t, client, 30*time.Millisecond)

	clock.Add(int64(options.dedupTTL + time.Nanosecond))
	notifier.Notify(context.Background(), remoteAddr, attemptedUUID)
	second := readUnknownUserNotification(t, client, time.Second)
	if got, want := second.GetAttemptedUuid(), attemptedUUID.String(); got != want {
		t.Fatalf("attempted UUID after TTL = %q, want %q", got, want)
	}
}

func TestUnknownUserNotifierQueueDropIsNonBlockingAndRetryable(t *testing.T) {
	options := defaultUnknownUserNotifierOptions()
	options.eventQueueSize = 1
	notifier := newUnknownUserNotifierState(context.Background(), nil, options)
	notifier.clientCount.Store(1)
	defer notifier.Close()

	firstUUID := mustParseUUID(t, "01234567-89ab-cdef-0123-456789abcdef")
	droppedUUID := mustParseUUID(t, "11111111-2222-3333-4444-555555555555")
	notifier.Notify(context.Background(), nil, firstUUID)

	started := time.Now()
	notifier.Notify(context.Background(), nil, droppedUUID)
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Notify blocked for %s on a full event queue", elapsed)
	}

	select {
	case <-notifier.events:
	default:
		t.Fatal("first event was not queued")
	}

	notifier.Notify(context.Background(), nil, droppedUUID)
	select {
	case event := <-notifier.events:
		if got, want := event.key, droppedUUID.String(); got != want {
			t.Fatalf("queued UUID = %q, want %q", got, want)
		}
	default:
		t.Fatal("dropped UUID remained deduplicated after queue space became available")
	}
}

func TestWriteNotificationFrameHandlesPartialWrites(t *testing.T) {
	conn := &shortWriteConn{maxWrite: 3}
	frame := []byte("length-prefixed-protobuf")
	now := time.Unix(1_725_000_000, 0)
	timeout := 2 * time.Second

	frameWritten, err := writeNotificationFrame(conn, frame, timeout, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !frameWritten {
		t.Fatal("full frame write was not reported")
	}
	if got := conn.buffer.Bytes(); !bytes.Equal(got, frame) {
		t.Fatalf("written frame = %q, want %q", got, frame)
	}
	if got := len(conn.deadlines); got != 2 {
		t.Fatalf("write deadline calls = %d, want 2", got)
	}
	if got, want := conn.deadlines[0], now.Add(timeout); !got.Equal(want) {
		t.Fatalf("write deadline = %s, want %s", got, want)
	}
	if got := conn.deadlines[1]; !got.IsZero() {
		t.Fatalf("write deadline was not cleared: %s", got)
	}
}

func TestWriteNotificationFrameRejectsZeroWrite(t *testing.T) {
	conn := &shortWriteConn{}
	frameWritten, err := writeNotificationFrame(conn, []byte("frame"), time.Second, time.Now)
	if frameWritten {
		t.Fatal("zero-byte write was reported as a full frame")
	}
	if !stderrors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestWriteNotificationFrameTimesOut(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	started := time.Now()
	frameWritten, err := writeNotificationFrame(server, []byte("frame"), 20*time.Millisecond, time.Now)
	if frameWritten {
		t.Fatal("timed-out write was reported as a full frame")
	}
	var netErr net.Error
	if !stderrors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("write error = %v, want timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("write deadline was not enforced promptly: %s", elapsed)
	}
}

func TestUnknownUserNotifierSlowClientDoesNotBlockNotify(t *testing.T) {
	options := defaultUnknownUserNotifierOptions()
	options.eventQueueSize = 8
	options.clientQueueSize = 1
	options.maxClients = 1
	options.writeTimeout = 5 * time.Second

	notifier := newUnknownUserNotifierState(context.Background(), nil, options)
	notifier.wg.Add(1)
	go notifier.broadcast()

	conn := newBlockingNotificationConn()
	if !notifier.addClient(conn) {
		t.Fatal("failed to add notification client")
	}
	client := notifier.clientSnapshot()[0]

	notifier.Notify(context.Background(), nil, uuid.New())
	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("notification writer did not start")
	}

	notifier.Notify(context.Background(), nil, uuid.New())
	waitFor(t, time.Second, func() bool {
		return len(client.queue) == 1
	})

	started := time.Now()
	notifier.Notify(context.Background(), nil, uuid.New())
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Notify blocked for %s on a slow client", elapsed)
	}

	waitFor(t, time.Second, func() bool {
		return notifier.clientCount.Load() == 0
	})

	closed := make(chan error, 1)
	go func() {
		closed <- notifier.Close()
	}()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("notifier close blocked on a slow client")
	}
}

func TestUnknownUserNotifierFailedWriteReleasesDedupReservation(t *testing.T) {
	options := defaultUnknownUserNotifierOptions()
	options.eventQueueSize = 1
	options.clientQueueSize = 1

	notifier := newUnknownUserNotifierState(context.Background(), nil, options)
	notifier.wg.Add(1)
	go notifier.broadcast()

	conn := newFailingWriteNotificationConn()
	if !notifier.addClient(conn) {
		t.Fatal("failed to add notification client")
	}

	attemptedUUID := mustParseUUID(t, "01234567-89ab-cdef-0123-456789abcdef")
	notifier.Notify(context.Background(), nil, attemptedUUID)
	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("notification writer did not attempt the frame")
	}
	waitFor(t, time.Second, func() bool {
		return notifier.clientCount.Load() == 0 && notifier.dedup.Len() == 0
	})

	token, allowed := notifier.dedup.Reserve(attemptedUUID.String(), options.now())
	if !allowed {
		t.Fatal("failed UDS write suppressed a retry for the full deduplication TTL")
	}
	notifier.dedup.Forget(attemptedUUID.String(), token)
	if err := notifier.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownUserNotifierClientLimit(t *testing.T) {
	options := defaultUnknownUserNotifierOptions()
	options.maxClients = 1
	notifier := newUnknownUserNotifierState(context.Background(), nil, options)

	first := newBlockingNotificationConn()
	if !notifier.addClient(first) {
		t.Fatal("first client was rejected")
	}
	second := newBlockingNotificationConn()
	if notifier.addClient(second) {
		t.Fatal("client beyond configured limit was accepted")
	}
	select {
	case <-second.closed:
	default:
		t.Fatal("rejected client was not closed")
	}
	if got := notifier.clientCount.Load(); got != 1 {
		t.Fatalf("active clients = %d, want 1", got)
	}
	if err := notifier.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownUserNotifierCloseRemovesSocketAndClients(t *testing.T) {
	socketPath := notificationSocketPath(t)
	notifier, err := newUnknownUserNotifier(context.Background(), socketPath)
	if err != nil {
		t.Fatal(err)
	}

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waitFor(t, time.Second, func() bool {
		return notifier.clientCount.Load() == 1
	})

	if err := notifier.Close(); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := os.Lstat(socketPath); !stderrors.Is(err, os.ErrNotExist) {
		t.Fatalf("notification socket still exists after close: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	if _, err := client.Read(buffer[:]); err == nil {
		t.Fatal("client connection remained open after notifier close")
	}

	notifier.Notify(context.Background(), nil, uuid.New())
}

func TestUnknownUserNotifierDoesNotTakeOverLiveSocket(t *testing.T) {
	socketPath := notificationSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	probeAccepted := acceptNotificationConnection(listener)
	notifier, err := newUnknownUserNotifier(context.Background(), socketPath)
	if err == nil {
		if notifier != nil {
			_ = notifier.Close()
		}
		t.Fatal("live notification socket was taken over")
	}
	select {
	case err := <-probeAccepted:
		if err != nil {
			t.Fatalf("accept liveness probe: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("existing listener did not receive liveness probe")
	}
	if info, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("live notification socket was removed: %v", err)
	} else if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("live notification path mode = %s, want socket", info.Mode())
	}

	connectionAccepted := acceptNotificationConnection(listener)
	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial original listener after rejected takeover: %v", err)
	}
	_ = client.Close()
	select {
	case err := <-connectionAccepted:
		if err != nil {
			t.Fatalf("original listener stopped accepting: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("original listener stopped accepting after rejected takeover")
	}
}

func TestUnknownUserNotifierReplacesStaleSocket(t *testing.T) {
	socketPath := notificationSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		t.Fatalf("listener type = %T, want *net.UnixListener", listener)
	}
	unixListener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("stale socket was not retained for test: %v", err)
	}

	notifier, err := newUnknownUserNotifier(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("replace stale notification socket: %v", err)
	}
	if err := notifier.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownUserNotifierRefusesToReplaceRegularFile(t *testing.T) {
	socketPath := notificationSocketPath(t)
	const contents = "do not replace"
	if err := os.WriteFile(socketPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	notifier, err := newUnknownUserNotifier(context.Background(), socketPath)
	if err == nil {
		if notifier != nil {
			_ = notifier.Close()
		}
		t.Fatal("regular file was accepted as notification socket path")
	}
	data, readErr := os.ReadFile(socketPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got := string(data); got != contents {
		t.Fatalf("regular file contents = %q, want %q", got, contents)
	}
}

func mustParseUUID(t *testing.T, value string) uuid.UUID {
	t.Helper()
	parsed, err := uuid.ParseString(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func notificationSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "xray-notify-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove temporary socket directory: %v", err)
		}
	})
	return filepath.Join(directory, "notify.sock")
}

func readUnknownUserNotification(t *testing.T, conn net.Conn, timeout time.Duration) *UnknownUserAttempt {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}

	var lengthBuffer [4]byte
	if _, err := io.ReadFull(conn, lengthBuffer[:]); err != nil {
		t.Fatal(err)
	}
	length := binary.BigEndian.Uint32(lengthBuffer[:])
	if length > 64*1024 {
		t.Fatalf("notification payload is unexpectedly large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	var attempt UnknownUserAttempt
	if err := proto.Unmarshal(payload, &attempt); err != nil {
		t.Fatal(err)
	}
	return &attempt
}

func expectNoNotification(t *testing.T, conn net.Conn, timeout time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	_, err := conn.Read(buffer[:])
	var netErr net.Error
	if !stderrors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read error = %v, want timeout", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not met before timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

func acceptNotificationConnection(listener net.Listener) <-chan error {
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = conn.Close()
		}
		accepted <- err
	}()
	return accepted
}

type notificationTestAddr string

func (a notificationTestAddr) Network() string {
	return "test"
}

func (a notificationTestAddr) String() string {
	return string(a)
}

type shortWriteConn struct {
	buffer    bytes.Buffer
	maxWrite  int
	deadlines []time.Time
}

func (c *shortWriteConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *shortWriteConn) Write(buffer []byte) (int, error) {
	if c.maxWrite == 0 {
		return 0, nil
	}
	if len(buffer) > c.maxWrite {
		buffer = buffer[:c.maxWrite]
	}
	return c.buffer.Write(buffer)
}

func (*shortWriteConn) Close() error {
	return nil
}

func (*shortWriteConn) LocalAddr() net.Addr {
	return notificationTestAddr("local")
}

func (*shortWriteConn) RemoteAddr() net.Addr {
	return notificationTestAddr("remote")
}

func (*shortWriteConn) SetDeadline(time.Time) error {
	return nil
}

func (*shortWriteConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *shortWriteConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

type blockingNotificationConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingNotificationConn() *blockingNotificationConn {
	return &blockingNotificationConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockingNotificationConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingNotificationConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() {
		close(c.writeStarted)
	})
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingNotificationConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (*blockingNotificationConn) LocalAddr() net.Addr {
	return notificationTestAddr("local")
}

func (*blockingNotificationConn) RemoteAddr() net.Addr {
	return notificationTestAddr("remote")
}

func (*blockingNotificationConn) SetDeadline(time.Time) error {
	return nil
}

func (*blockingNotificationConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*blockingNotificationConn) SetWriteDeadline(time.Time) error {
	return nil
}

type failingWriteNotificationConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

func newFailingWriteNotificationConn() *failingWriteNotificationConn {
	return &failingWriteNotificationConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *failingWriteNotificationConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *failingWriteNotificationConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() {
		close(c.writeStarted)
	})
	return 0, io.ErrClosedPipe
}

func (c *failingWriteNotificationConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (*failingWriteNotificationConn) LocalAddr() net.Addr {
	return notificationTestAddr("local")
}

func (*failingWriteNotificationConn) RemoteAddr() net.Addr {
	return notificationTestAddr("remote")
}

func (*failingWriteNotificationConn) SetDeadline(time.Time) error {
	return nil
}

func (*failingWriteNotificationConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*failingWriteNotificationConn) SetWriteDeadline(time.Time) error {
	return nil
}
