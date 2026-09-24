package detector

import "github.com/xtls/xray-core/common"

func sniffTCP(payload []byte) error {
	if len(payload) < 20 {
		return common.ErrNoClue
	}
	if payload[0] == 19 && string(payload[1:20]) == "BitTorrent protocol" {
		return nil
	}
	return errNotBittorrent
}
