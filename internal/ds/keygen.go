package ds

import (
	"crypto/rand"
	"math/big"
)

func KeyGen(pp *Params, n int) (*SecretKey, *PublicKey) {
	if n > 0 {
		pp.N = n
	}
	const bits = 256
	f0, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), bits))
	s1p, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), bits))
	return &SecretKey{F0: f0}, &PublicKey{S1p: s1p}
}
