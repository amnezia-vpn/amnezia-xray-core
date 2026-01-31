package congestion

import (
	"github.com/amnezia-vpn/amnezia-xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/amnezia-vpn/amnezia-xray-core/transport/internet/hysteria/congestion/brutal"
	"github.com/apernet/quic-go"
)

func UseBBR(conn *quic.Conn) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn *quic.Conn, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
