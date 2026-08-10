//go:build windows

package inbound

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isNotificationSocketConnectionRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
