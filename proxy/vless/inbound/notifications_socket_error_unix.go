//go:build !windows

package inbound

import (
	"errors"
	"syscall"
)

func isNotificationSocketConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
