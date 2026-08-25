package detector

import "github.com/xtls/xray-core/common"

func sniffUTP(payload []byte) error {
	if len(payload) < 20 {
		return common.ErrNoClue
	}
	if payload[0]>>4 > 4 || payload[0]&0x0f != 1 {
		return errNotBittorrent
	}
	extension := payload[1]
	if extension != 0 && extension != 1 && extension != 3 {
		return errNotBittorrent
	}
	if extension == 0 && payload[2] == 0 && payload[3] == 0 {
		return errNotBittorrent
	}
	for offset := 20; extension != 0; {
		if extension != 1 && extension != 3 {
			return errNotBittorrent
		}
		if offset+2 > len(payload) {
			return common.ErrNoClue
		}
		next := payload[offset]
		offset += 2 + int(payload[offset+1])
		if offset > len(payload) {
			return common.ErrNoClue
		}
		extension = next
	}
	return nil
}
