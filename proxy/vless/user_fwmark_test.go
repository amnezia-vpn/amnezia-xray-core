package vless

import (
	"math"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
)

func TestValidateUserFwmark(t *testing.T) {
	tests := []struct {
		name    string
		mark    uint32
		wantErr bool
	}{
		{name: "disabled", mark: 0},
		{name: "below range", mark: 999_999_999, wantErr: true},
		{name: "minimum", mark: 1_000_000_000},
		{name: "maximum", mark: math.MaxUint32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateUserFwmark(test.mark)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateUserFwmark(%d) error = %v, wantErr %v", test.mark, err, test.wantErr)
			}
		})
	}
}

func TestMemoryValidatorRejectsInvalidFwmarkWithoutMutation(t *testing.T) {
	id := uuid.New()
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{ID: protocol.NewID(id)},
		Email:   "invalid-fwmark@example.com",
		Fwmark:  999_999_999,
	}
	validator := new(MemoryValidator)
	if err := validator.Add(user); err == nil {
		t.Fatal("invalid fwmark unexpectedly accepted")
	}
	if validator.GetCount() != 0 || validator.GetByEmail(user.Email) != nil || validator.Get(id) != nil {
		t.Fatal("rejected user mutated the validator")
	}
}

func TestUserFwmarkRoundTrip(t *testing.T) {
	id := uuid.New()
	original := &protocol.User{
		Account: serial.ToTypedMessage(&Account{Id: id.String()}),
		Fwmark:  math.MaxUint32,
	}
	memoryUser, err := original.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	if memoryUser.Fwmark != math.MaxUint32 {
		t.Fatalf("memory fwmark = %d, want %d", memoryUser.Fwmark, uint32(math.MaxUint32))
	}
	if got := protocol.ToProtoUser(memoryUser).GetFwmark(); got != math.MaxUint32 {
		t.Fatalf("protobuf fwmark = %d, want %d", got, uint32(math.MaxUint32))
	}
}
