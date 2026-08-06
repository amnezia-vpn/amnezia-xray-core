package command

import (
	"math"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

func TestAddUserOperationFwmarkRoundTrip(t *testing.T) {
	original := &AddUserOperation{User: &protocol.User{Fwmark: math.MaxUint32}}
	wire, err := proto.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(AddUserOperation)
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetUser().GetFwmark() != uint32(math.MaxUint32) {
		t.Fatalf("fwmark = %d, want %d", decoded.GetUser().GetFwmark(), uint32(math.MaxUint32))
	}
}
