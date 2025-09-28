package ds

import "math/big"

type Params struct {
	P *big.Int // 모듈러
	K uint     // (선택) Barrett 등에서 2^K 지수
	N int
}

func DefaultParams() *Params {
	// 데모용: 2^32-5 (큰 소수)
	p := big.NewInt(4294967291)
	return &Params{P: p, K: 32, N: 1}
}

// (선택) 2^K
func (pp *Params) R() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), pp.K)
}
