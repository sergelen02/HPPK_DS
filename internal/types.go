package ds

import "math/big"

// Params: p, L=bitlen(p), K(Barrett), R=2^K
type Params struct {
	P *big.Int
	L int
	K int
	R *big.Int
}

type SecretKey struct {
	R1, S1 *big.Int
	R2, S2 *big.Int
	FCoeffs []*big.Int // f_0..f_λ
	HCoeffs []*big.Int // h_0..h_λ
	Lambda  int
}

type PublicKey struct {
	S1p, S2p  *big.Int
	Pprime    []*big.Int
	Qprime    []*big.Int
	MuP       []*big.Int // μ
	MuQ       []*big.Int // ν
	N         int
	M         int
	Lambda    int
}

type Signature struct{ F, H *big.Int }
