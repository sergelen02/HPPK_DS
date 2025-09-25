package ds

import "math/big"

// Secret Key: f(x)=f0+f1x, h(x)=h0+h1x, (R1,S1),(R2,S2), β
type SecretKey struct {
	F0, F1 *big.Int
	H0, H1 *big.Int
	R1, S1 *big.Int
	R2, S2 *big.Int
	Beta   *big.Int
}

// Public Key: p′, q′, μ, ν, s1, s2  (Barrett-확장 계수들)
type PublicKey struct {
	Pprime []*big.Int // p′_i
	Qprime []*big.Int // q′_i
	Mu     []*big.Int // μ_i
	Nu     []*big.Int // ν_i
	S1p    *big.Int   // s1
	S2p    *big.Int   // s2
}

// Signature: (F, H)
type Signature struct {
	F *big.Int
	H *big.Int
}
