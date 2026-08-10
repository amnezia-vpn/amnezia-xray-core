//go:build windows

package inbound

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsNotificationSocketConnectionRefused(t *testing.T) {
	err := &net.OpError{
		Op:  "dial",
		Net: "unix",
		Err: &os.SyscallError{
			Syscall: "connect",
			Err:     windows.WSAECONNREFUSED,
		},
	}

	if !isNotificationSocketConnectionRefused(err) {
		t.Fatalf("wrapped WSAECONNREFUSED was not recognized: %v", err)
	}
	if isNotificationSocketConnectionRefused(os.ErrPermission) {
		t.Fatal("permission error was recognized as connection refused")
	}
}
