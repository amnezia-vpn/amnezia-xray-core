package internet_test

import (
	"context"
	goerrors "errors"
	"math"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	. "github.com/xtls/xray-core/transport/internet"
)

func TestSockOptMark(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: func(b []byte) []byte {
			return b
		},
	}
	dest, err := tcpServer.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpServer.Close()

	const mark = uint32(math.MaxUint32)
	dialer := DefaultSystemDialer{}
	conn, err := dialer.Dial(context.Background(), nil, dest, &SocketConfig{Mark: mark, StrictBinding: true})
	if goerrors.Is(err, syscall.EPERM) || goerrors.Is(err, syscall.EACCES) {
		t.Skipf("requires permission to set SO_MARK: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	err = rawConn.Control(func(fd uintptr) {
		m, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
		if err != nil {
			t.Error(err)
			return
		}
		if uint32(m) != mark {
			t.Fatalf("connection mark = %d, want %d", uint32(m), mark)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}
