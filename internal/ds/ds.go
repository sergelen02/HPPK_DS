package ds

import (
	"errors"
	"math/big"
)

func Hello() string { return "ds package is alive" }

func KeyGenDefault() (*Params, *SecretKey, *PublicKey, error) {
	pp := DefaultParams()
	sk, pk, err := KeyGen(pp, 1, 1, 1)
	if err != nil { return nil, nil, nil, err }
	return pp, sk, pk, nil
}

func KeyGenWith(pp *Params, n, m, lambda int) (*SecretKey, *PublicKey, error) {
	if pp == nil || pp.P == nil || pp.R == nil {
		return nil, nil, errors.New("KeyGenWith: nil or incomplete params")
	}
	return KeyGen(pp, n, m, lambda)
}

func KeyGenFromPrime(p *big.Int, K int, n, m, lambda int) (*Params, *SecretKey, *PublicKey, error) {
	if p == nil || p.Sign() <= 0 {
		return nil, nil, nil, errors.New("KeyGenFromPrime: invalid p")
	}
	L := p.BitLen()
	if K < L+32 { K = L + 32 }
	pp := &Params{P: new(big.Int).Set(p), L: L, K: K, R: new(big.Int).Lsh(big.NewInt(1), uint(K))}
	sk, pk, err := KeyGen(pp, n, m, lambda)
	if err != nil { return nil, nil, nil, err }
	return pp, sk, pk, nil
}

func SignMessage(pp *Params, sk *SecretKey, msg []byte) (*Signature, *big.Int, error) {
	return Sign(pp, sk, msg)
}
func VerifyMessage(pp *Params, pk *PublicKey, sig *Signature, msg []byte) bool {
	return Verify(pp, pk, sig, msg)
}
