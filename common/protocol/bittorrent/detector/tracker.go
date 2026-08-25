package detector

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common"
)

func sniffUDPTracker(payload []byte) error {
	if len(payload) == 0 {
		return common.ErrNoClue
	}
	if len(payload) == 16 &&
		binary.BigEndian.Uint64(payload[:8]) == 0x41727101980 &&
		binary.BigEndian.Uint32(payload[8:12]) == 0 {
		return nil
	}
	if len(payload) == 98 && binary.BigEndian.Uint32(payload[8:12]) == 1 {
		event := binary.BigEndian.Uint32(payload[80:84])
		port := binary.BigEndian.Uint16(payload[96:98])
		if event <= 3 && port != 0 {
			return nil
		}
	}
	if len(payload) >= 36 && (len(payload)-16)%20 == 0 &&
		binary.BigEndian.Uint32(payload[8:12]) == 2 {
		return nil
	}
	return errNotBittorrent
}
