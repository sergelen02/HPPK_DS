package ds

import "math/big"

type Params struct {
	P *big.Int // prime modulus
	K int      // Barrett exponent; R=2^K
}

func DefaultParams() *Params {
	// 데모 값(실험 시 교체 가능)
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(59)) // 2^64-59
	return &Params{P: p, K: 208}
}

func (pp *Params) R() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(pp.K))
}
