package conf_test

import (
	"testing"

	"github.com/amnezia-vpn/amnezia-xray-core/common/serial"
	. "github.com/amnezia-vpn/amnezia-xray-core/infra/conf"
	"github.com/amnezia-vpn/amnezia-xray-core/proxy/blackhole"
)

func TestHTTPResponseJSON(t *testing.T) {
	creator := func() Buildable {
		return new(BlackholeConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"response": {
					"type": "http"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPResponse{}),
			},
		},
		{
			Input:  `{}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{},
		},
	})
}
