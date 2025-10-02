package ds

import (
	"errors"
	"math/big"
)

// f(x), h(x) 평가 (mod p) → F = f(x)*R2^{-1} (mod S2),  H = h(x)*R1^{-1} (mod S1)
type Signature struct{ F, H *big.Int }

func Sign(pp *Params, sk *SecretKey, msg []byte) (*Signature, *big.Int, error) {
	if pp == nil || sk == nil || pp.P == nil {
		return nil, nil, errors.New("nil params/secret")
	}
	x := hashToX(pp.P, msg)

	// 역원 체크
	r2Inv := new(big.Int).ModInverse(sk.R2, sk.S2)
	if r2Inv == nil { return nil, nil, errors.New("R2 has no inverse mod S2") }
	r1Inv := new(big.Int).ModInverse(sk.R1, sk.S1)
	if r1Inv == nil { return nil, nil, errors.New("R1 has no inverse mod S1") }

	fx := evalPoly(sk.FCoeffs, x, pp.P)
	hx := evalPoly(sk.HCoeffs, x, pp.P)

	F := new(big.Int).Mul(fx, r2Inv)
	F.Mod(F, sk.S2)
	H := new(big.Int).Mul(hx, r1Inv)
	H.Mod(H, sk.S1)

	return &Signature{F: F, H: H}, x, nil
}
