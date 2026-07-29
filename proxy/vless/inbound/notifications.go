package inbound

import (
	"container/list"
	"context"
	"encoding/binary"
	stderrors "errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	defaultNotificationDedupTTL        = 30 * time.Second
	defaultNotificationDedupEntries    = 4096
	defaultNotificationEventQueueSize  = 256
	defaultNotificationClientQueueSize = 32
	defaultNotificationMaxClients      = 8
	defaultNotificationWriteTimeout    = 2 * time.Second

	initialNotificationAcceptRetry = 5 * time.Millisecond
	maxNotificationAcceptRetry     = time.Second
	notificationSocketProbeTimeout = 100 * time.Millisecond
)

type unknownUserNotifierOptions struct {
	dedupTTL        time.Duration
	dedupEntries    int
	eventQueueSize  int
	clientQueueSize int
	maxClients      int
	writeTimeout    time.Duration
	now             func() time.Time
}

func defaultUnknownUserNotifierOptions() unknownUserNotifierOptions {
	return unknownUserNotifierOptions{
		dedupTTL:        defaultNotificationDedupTTL,
		dedupEntries:    defaultNotificationDedupEntries,
		eventQueueSize:  defaultNotificationEventQueueSize,
		clientQueueSize: defaultNotificationClientQueueSize,
		maxClients:      defaultNotificationMaxClients,
		writeTimeout:    defaultNotificationWriteTimeout,
		now:             time.Now,
	}
}

func (o unknownUserNotifierOptions) validate() error {
	switch {
	case o.dedupTTL <= 0:
		return errors.New("notification deduplication TTL must be positive")
	case o.dedupEntries <= 0:
		return errors.New("notification deduplication capacity must be positive")
	case o.eventQueueSize <= 0:
		return errors.New("notification event queue size must be positive")
	case o.clientQueueSize <= 0:
		return errors.New("notification client queue size must be positive")
	case o.maxClients <= 0:
		return errors.New("notification client limit must be positive")
	case o.writeTimeout <= 0:
		return errors.New("notification write timeout must be positive")
	case o.now == nil:
		return errors.New("notification clock must not be nil")
	default:
		return nil
	}
}

type unknownUserNotification struct {
	key   string
	token uint64
	frame []byte
}

type unknownUserNotificationDelivery struct {
	notifier     *unknownUserNotifier
	notification unknownUserNotification
	pending      atomic.Int32
	succeeded    atomic.Bool
}

func newUnknownUserNotificationDelivery(
	notifier *unknownUserNotifier,
	notification unknownUserNotification,
) *unknownUserNotificationDelivery {
	delivery := &unknownUserNotificationDelivery{
		notifier:     notifier,
		notification: notification,
	}
	// The broadcaster owns one reference until it has finished enqueueing the
	// delivery. This prevents a fast writer from completing before all client
	// references have been registered.
	delivery.pending.Store(1)
	return delivery
}

func (d *unknownUserNotificationDelivery) addRecipient() {
	d.pending.Add(1)
}

func (d *unknownUserNotificationDelivery) complete(succeeded bool) {
	if succeeded {
		d.succeeded.Store(true)
	}
	if d.pending.Add(-1) == 0 && !d.succeeded.Load() {
		// A full UDS write is the strongest delivery signal available without
		// changing the existing one-way wire protocol to require acknowledgements.
		d.notifier.dedup.Forget(d.notification.key, d.notification.token)
	}
}

type unknownUserNotificationClient struct {
	conn      net.Conn
	queue     chan *unknownUserNotificationDelivery
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	closing   bool
}

func (c *unknownUserNotificationClient) Close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		close(c.done)
		c.mu.Unlock()
		_ = c.conn.Close()
	})
}

func (c *unknownUserNotificationClient) tryEnqueue(
	delivery *unknownUserNotificationDelivery,
) (queued bool, full bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closing {
		return false, false
	}
	select {
	case c.queue <- delivery:
		return true, false
	default:
		return false, true
	}
}

func (c *unknownUserNotificationClient) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

type unknownUserNotifier struct {
	ctx      context.Context
	listener net.Listener
	options  unknownUserNotifierOptions

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup

	clientsMu   sync.Mutex
	clients     map[*unknownUserNotificationClient]struct{}
	closing     bool
	clientCount atomic.Int32

	events chan unknownUserNotification
	dedup  *unknownUserNotificationDeduplicator
}

func newUnknownUserNotifier(ctx context.Context, socketPath string) (*unknownUserNotifier, error) {
	return newUnknownUserNotifierWithOptions(ctx, socketPath, defaultUnknownUserNotifierOptions())
}

func newUnknownUserNotifierWithOptions(
	ctx context.Context,
	socketPath string,
	options unknownUserNotifierOptions,
) (*unknownUserNotifier, error) {
	if socketPath == "" {
		return nil, nil
	}
	if err := options.validate(); err != nil {
		return nil, err
	}

	listener, err := listenUnknownUserNotifications(socketPath)
	if err != nil {
		return nil, err
	}

	notifier := newUnknownUserNotifierState(ctx, listener, options)
	notifier.wg.Add(2)
	go notifier.acceptClients()
	go notifier.broadcast()
	return notifier, nil
}

func newUnknownUserNotifierState(
	ctx context.Context,
	listener net.Listener,
	options unknownUserNotifierOptions,
) *unknownUserNotifier {
	return &unknownUserNotifier{
		ctx:      ctx,
		listener: listener,
		options:  options,
		done:     make(chan struct{}),
		clients:  make(map[*unknownUserNotificationClient]struct{}),
		events:   make(chan unknownUserNotification, options.eventQueueSize),
		dedup:    newUnknownUserNotificationDeduplicator(options.dedupTTL, options.dedupEntries),
	}
}

func listenUnknownUserNotifications(socketPath string) (net.Listener, error) {
	if strings.HasPrefix(socketPath, "@") {
		return nil, errors.New("VLESS notification socket requires a filesystem path")
	}

	info, err := os.Lstat(socketPath)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace non-socket notification path: ", socketPath)
		}
		if err := removeStaleUnknownUserNotificationSocket(socketPath); err != nil {
			return nil, err
		}
	case stderrors.Is(err, os.ErrNotExist):
	default:
		return nil, errors.New("failed to inspect notification socket path").Base(err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, errors.New("failed to listen on notification UNIX socket").Base(err)
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, errors.New("failed to chmod notification UNIX socket").Base(err)
	}
	return listener, nil
}

func removeStaleUnknownUserNotificationSocket(socketPath string) error {
	conn, err := net.DialTimeout("unix", socketPath, notificationSocketProbeTimeout)
	if err == nil {
		_ = conn.Close()
		return errors.New("notification UNIX socket is already in use: ", socketPath)
	}
	if !stderrors.Is(err, syscall.ECONNREFUSED) && !stderrors.Is(err, os.ErrNotExist) {
		return errors.New("failed to verify existing notification UNIX socket is stale").Base(err)
	}
	if err := os.Remove(socketPath); err != nil && !stderrors.Is(err, os.ErrNotExist) {
		return errors.New("failed to remove stale notification socket").Base(err)
	}
	return nil
}

func (n *unknownUserNotifier) Notify(ctx context.Context, remoteAddr net.Addr, attemptedUUID uuid.UUID) {
	if n == nil || n.clientCount.Load() == 0 || n.closed() {
		return
	}

	now := n.options.now()
	key := attemptedUUID.String()
	token, allowed := n.dedup.Reserve(key, now)
	if !allowed {
		return
	}

	frame, err := marshalUnknownUserNotification(remoteAddr, key, now)
	if err != nil {
		n.dedup.Forget(key, token)
		errors.LogErrorInner(ctx, err, "error marshalling unknown VLESS user notification")
		return
	}

	event := unknownUserNotification{
		key:   key,
		token: token,
		frame: frame,
	}
	select {
	case n.events <- event:
	case <-n.done:
		n.dedup.Forget(key, token)
	default:
		n.dedup.Forget(key, token)
	}
}

func marshalUnknownUserNotification(remoteAddr net.Addr, attemptedUUID string, now time.Time) ([]byte, error) {
	var remoteIP string
	var remotePort int32
	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		remoteIP = addr.IP.String()
		remotePort = int32(addr.Port)
	case nil:
	default:
		remoteIP = addr.String()
	}

	payload, err := proto.Marshal(&UnknownUserAttempt{
		RemoteIp:      remoteIP,
		RemotePort:    remotePort,
		AttemptedUuid: attemptedUUID,
		Timestamp:     now.Unix(),
	})
	if err != nil {
		return nil, err
	}

	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame, nil
}

func (n *unknownUserNotifier) acceptClients() {
	defer n.wg.Done()

	retryDelay := initialNotificationAcceptRetry
	for {
		conn, err := n.listener.Accept()
		if err == nil {
			retryDelay = initialNotificationAcceptRetry
			n.addClient(conn)
			continue
		}
		if n.closed() {
			return
		}

		errors.LogDebugInner(n.ctx, err, "error accepting notification UNIX socket connection")
		timer := time.NewTimer(retryDelay)
		select {
		case <-timer.C:
		case <-n.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
		retryDelay *= 2
		if retryDelay > maxNotificationAcceptRetry {
			retryDelay = maxNotificationAcceptRetry
		}
	}
}

func (n *unknownUserNotifier) addClient(conn net.Conn) bool {
	client := &unknownUserNotificationClient{
		conn:  conn,
		queue: make(chan *unknownUserNotificationDelivery, n.options.clientQueueSize),
		done:  make(chan struct{}),
	}

	n.clientsMu.Lock()
	if n.closing || len(n.clients) >= n.options.maxClients {
		n.clientsMu.Unlock()
		client.Close()
		return false
	}
	n.clients[client] = struct{}{}
	n.clientCount.Add(1)
	n.wg.Add(2)
	n.clientsMu.Unlock()

	go n.writeClient(client)
	go n.watchClient(client)
	return true
}

func (n *unknownUserNotifier) writeClient(client *unknownUserNotificationClient) {
	defer n.wg.Done()
	defer func() {
		n.removeClient(client)
		n.failQueuedDeliveries(client)
	}()

	for {
		select {
		case delivery := <-client.queue:
			frameWritten, err := writeNotificationFrame(
				client.conn,
				delivery.notification.frame,
				n.options.writeTimeout,
				n.options.now,
			)
			delivery.complete(frameWritten)
			if err != nil {
				if !n.closed() {
					errors.LogDebugInner(n.ctx, err, "error writing to notification UNIX socket client")
				}
				return
			}
		case <-client.done:
			return
		case <-n.done:
			return
		}
	}
}

func (*unknownUserNotifier) failQueuedDeliveries(client *unknownUserNotificationClient) {
	for {
		select {
		case delivery := <-client.queue:
			delivery.complete(false)
		default:
			return
		}
	}
}

func (n *unknownUserNotifier) watchClient(client *unknownUserNotificationClient) {
	defer n.wg.Done()
	defer n.removeClient(client)

	buffer := make([]byte, 1)
	for {
		if _, err := client.conn.Read(buffer); err != nil {
			return
		}
	}
}

func writeNotificationFrame(
	conn net.Conn,
	frame []byte,
	timeout time.Duration,
	now func() time.Time,
) (frameWritten bool, err error) {
	if err := conn.SetWriteDeadline(now().Add(timeout)); err != nil {
		return false, err
	}
	defer func() {
		if clearErr := conn.SetWriteDeadline(time.Time{}); err == nil && clearErr != nil {
			err = clearErr
		}
	}()

	for len(frame) > 0 {
		written, writeErr := conn.Write(frame)
		if written < 0 || written > len(frame) {
			return false, io.ErrShortWrite
		}
		if written > 0 {
			frame = frame[written:]
		}
		if writeErr != nil {
			return len(frame) == 0, writeErr
		}
		if written == 0 {
			return false, io.ErrShortWrite
		}
	}
	return true, nil
}

func (n *unknownUserNotifier) broadcast() {
	defer n.wg.Done()

	for {
		select {
		case event := <-n.events:
			delivery := newUnknownUserNotificationDelivery(n, event)
			for _, client := range n.clientSnapshot() {
				if client.closed() {
					continue
				}
				delivery.addRecipient()
				queued, full := client.tryEnqueue(delivery)
				if !queued {
					delivery.complete(false)
				}
				if full {
					n.removeClient(client)
				}
			}
			delivery.complete(false)
		case <-n.done:
			return
		}
	}
}

func (n *unknownUserNotifier) clientSnapshot() []*unknownUserNotificationClient {
	n.clientsMu.Lock()
	defer n.clientsMu.Unlock()

	clients := make([]*unknownUserNotificationClient, 0, len(n.clients))
	for client := range n.clients {
		clients = append(clients, client)
	}
	return clients
}

func (n *unknownUserNotifier) removeClient(client *unknownUserNotificationClient) {
	n.clientsMu.Lock()
	_, found := n.clients[client]
	if found {
		delete(n.clients, client)
		n.clientCount.Add(-1)
	}
	n.clientsMu.Unlock()

	if found {
		client.Close()
	}
}

func (n *unknownUserNotifier) closed() bool {
	select {
	case <-n.done:
		return true
	default:
		return false
	}
}

func (n *unknownUserNotifier) Close() error {
	if n == nil {
		return nil
	}

	n.closeOnce.Do(func() {
		n.clientsMu.Lock()
		n.closing = true
		clients := make([]*unknownUserNotificationClient, 0, len(n.clients))
		for client := range n.clients {
			clients = append(clients, client)
			delete(n.clients, client)
		}
		n.clientCount.Store(0)
		n.clientsMu.Unlock()

		close(n.done)
		if n.listener != nil {
			if err := n.listener.Close(); err != nil && !stderrors.Is(err, net.ErrClosed) {
				n.closeErr = err
			}
		}
		for _, client := range clients {
			client.Close()
		}
		n.wg.Wait()
	})
	return n.closeErr
}

type unknownUserNotificationDedupEntry struct {
	key     string
	token   uint64
	expires time.Time
}

type unknownUserNotificationDeduplicator struct {
	mu       sync.Mutex
	ttl      time.Duration
	capacity int
	next     uint64
	entries  map[string]*list.Element
	order    list.List
}

func newUnknownUserNotificationDeduplicator(
	ttl time.Duration,
	capacity int,
) *unknownUserNotificationDeduplicator {
	return &unknownUserNotificationDeduplicator{
		ttl:      ttl,
		capacity: capacity,
		entries:  make(map[string]*list.Element, capacity),
	}
}

func (d *unknownUserNotificationDeduplicator) Reserve(key string, now time.Time) (uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.purgeExpired(now)
	if element, found := d.entries[key]; found {
		entry := element.Value.(*unknownUserNotificationDedupEntry)
		if now.Before(entry.expires) {
			return 0, false
		}
		d.remove(element)
	}
	for len(d.entries) >= d.capacity {
		d.remove(d.order.Front())
	}

	d.next++
	entry := &unknownUserNotificationDedupEntry{
		key:     key,
		token:   d.next,
		expires: now.Add(d.ttl),
	}
	d.entries[key] = d.order.PushBack(entry)
	return entry.token, true
}

func (d *unknownUserNotificationDeduplicator) Forget(key string, token uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	element, found := d.entries[key]
	if !found {
		return
	}
	entry := element.Value.(*unknownUserNotificationDedupEntry)
	if entry.token == token {
		d.remove(element)
	}
}

func (d *unknownUserNotificationDeduplicator) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

func (d *unknownUserNotificationDeduplicator) purgeExpired(now time.Time) {
	for element := d.order.Front(); element != nil; {
		entry := element.Value.(*unknownUserNotificationDedupEntry)
		if now.Before(entry.expires) {
			return
		}
		next := element.Next()
		d.remove(element)
		element = next
	}
}

func (d *unknownUserNotificationDeduplicator) remove(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*unknownUserNotificationDedupEntry)
	delete(d.entries, entry.key)
	d.order.Remove(element)
}
