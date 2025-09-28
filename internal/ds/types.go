package ds

import "math/big"

type SecretKey struct {
	F0 *big.Int
	// TODO: 실제 구현 시 필요한 필드 추가
}

type PublicKey struct {
	S1p    *big.Int
	S2p    *big.Int
	Pprime []*big.Int
	Qprime []*big.Int
	Mu     []*big.Int
	Nu     []*big.Int
}

type Signature struct {
	F *big.Int
	H *big.Int
}
