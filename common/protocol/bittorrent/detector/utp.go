package detector

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common"
)

func sniffUTP(payload []byte) error {
	if len(payload) < 20 {
		return common.ErrNoClue
	}
	if payload[0]>>4 > 4 || payload[0]&0x0f != 1 {
		return errNotBittorrent
	}
	if isDNSQuery(payload) {
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

func isDNSQuery(payload []byte) bool {
	if len(payload) < 17 || payload[2]&0x80 != 0 || payload[2]&0x78 != 0 {
		return false
	}
	if binary.BigEndian.Uint16(payload[4:6]) != 1 {
		return false
	}
	if binary.BigEndian.Uint16(payload[6:8]) != 0 ||
		binary.BigEndian.Uint16(payload[8:10]) != 0 {
		return false
	}
	additional := binary.BigEndian.Uint16(payload[10:12])
	if additional > 1 {
		return false
	}
	pos := 12
	for {
		if pos >= len(payload) {
			return false
		}
		labelLength := int(payload[pos])
		if labelLength == 0 {
			pos++
			break
		}
		if labelLength > 63 || pos+1+labelLength > len(payload) {
			return false
		}
		pos += 1 + labelLength
	}
	if pos+4 > len(payload) {
		return false
	}
	return additional == 1 || pos+4 == len(payload)
}
