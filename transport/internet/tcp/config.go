package tcp

import (
	"github.com/amnezia-vpn/amnezia-xray-core/common"
	"github.com/amnezia-vpn/amnezia-xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
