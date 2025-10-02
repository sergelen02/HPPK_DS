package ds

import "math/big"

// Params: p, L=bitlen(p), K(Barrett), R=2^K
type Params struct {
	P *big.Int
	L int
	K int
	R *big.Int
}

// p=2^64-59, K=L+32, R=1<<K
func DefaultParams() *Params {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(59))
	L := p.BitLen()
	K := L + 32
	R := new(big.Int).Lsh(big.NewInt(1), uint(K))
	return &Params{P: p, L: L, K: K, R: R}
}

// 선택: K 조정용
func (pp *Params) WithK(k int) {
	minK := pp.L + 32
	if k < minK {
		k = minK
	}
	pp.K = k
	pp.R = new(big.Int).Lsh(big.NewInt(1), uint(k))
}
