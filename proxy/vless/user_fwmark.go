package vless

import "github.com/xtls/xray-core/common/errors"

const MinUserFwmark uint32 = 1_000_000_000

func ValidateUserFwmark(mark uint32) error {
	if mark != 0 && mark < MinUserFwmark {
		return errors.New("VLESS user fwmark must be zero or at least ", MinUserFwmark).AtError()
	}
	return nil
}
