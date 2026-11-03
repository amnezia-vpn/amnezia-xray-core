//go:build integration

package inbound

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestConnectionTracker_TCPReset(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux loopback and TCP reset semantics")
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	oldClient, oldServer := dialTCPPair(t, listener, "127.0.0.2")
	defer oldClient.Close()
	defer oldServer.Close()
	currentClient, currentServer := dialTCPPair(t, listener, "127.0.0.3")
	defer currentClient.Close()
	defer currentServer.Close()

	tracker := newConnectionTracker()
	userID := [16]byte{1}
	releaseOld, resetErrs, err := tracker.register(
		userID,
		netip.MustParseAddr("127.0.0.2"),
		oldServer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(resetErrs) != 0 {
		t.Fatalf("registering old connection: %v", resetErrs)
	}
	defer releaseOld()

	if _, err := oldClient.Write([]byte("unread")); err != nil {
		t.Fatal(err)
	}
	releaseCurrent, resetErrs, err := tracker.register(
		userID,
		netip.MustParseAddr("127.0.0.3"),
		currentServer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(resetErrs) != 0 {
		t.Fatalf("registering current connection: %v", resetErrs)
	}
	defer releaseCurrent()

	if err := oldClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := oldClient.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("reading reset connection: got %v, want %v", err, syscall.ECONNRESET)
	}

	if err := currentClient.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := currentServer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := currentClient.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(currentServer, request); err != nil {
		t.Fatal(err)
	}
	if string(request) != "ping" {
		t.Fatalf("request: got %q, want %q", request, "ping")
	}
	if _, err := currentServer.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(currentClient, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("response: got %q, want %q", response, "pong")
	}
}

func dialTCPPair(t *testing.T, listener *net.TCPListener, sourceIP string) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	type acceptResult struct {
		connection *net.TCPConn
		err        error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		connection, err := listener.AcceptTCP()
		accepted <- acceptResult{connection: connection, err: err}
	}()

	client, err := net.DialTCP(
		"tcp4",
		&net.TCPAddr{IP: net.ParseIP(sourceIP)},
		listener.Addr().(*net.TCPAddr),
	)
	if err != nil {
		t.Fatal(err)
	}

	result := <-accepted
	if result.err != nil {
		client.Close()
		t.Fatal(result.err)
	}
	return client, result.connection
}
