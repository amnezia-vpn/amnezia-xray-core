package kcp

import (
	"crypto/cipher"
	"crypto/sha256"

	"github.com/amnezia-vpn/amnezia-xray-core/common/crypto"
)

func NewAEADAESGCMBasedOnSeed(seed string) cipher.AEAD {
	hashedSeed := sha256.Sum256([]byte(seed))
	return crypto.NewAesGcm(hashedSeed[:16])
}
