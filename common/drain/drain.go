package drain

import "io"

//go:generate go run github.com/amnezia-vpn/amnezia-xray-core/common/errors/errorgen

type Drainer interface {
	AcknowledgeReceive(size int)
	Drain(reader io.Reader) error
}
