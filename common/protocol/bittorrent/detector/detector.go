package detector

import (
	"errors"

	"github.com/xtls/xray-core/common"
)

type Header struct{}

func (*Header) Protocol() string { return "bittorrent" }
func (*Header) Domain() string   { return "" }

var errNotBittorrent = errors.New("not bittorrent header")

type packetSniffer func([]byte) error

func SniffTCP(payload []byte) (*Header, error) {
	if err := sniffTCP(payload); err != nil {
		return nil, err
	}
	return &Header{}, nil
}

func SniffUDP(payload []byte) (*Header, error) {
	needsMore := false
	for _, sniff := range []packetSniffer{sniffUTP, sniffDHT, sniffUDPTracker} {
		switch err := sniff(payload); err {
		case nil:
			return &Header{}, nil
		case common.ErrNoClue:
			needsMore = true
		case errNotBittorrent:
		default:
			return nil, err
		}
	}
	if needsMore {
		return nil, common.ErrNoClue
	}
	return nil, errNotBittorrent
}
