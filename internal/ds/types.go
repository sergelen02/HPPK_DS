package ds

import "math/big"

// Params: F_p의 소수 p, L=bitlen(p) 기반 Barrett 파라미터 K, R=2^K
type Params struct {
	P *big.Int // prime modulus for F_p
	L int      // bit-length of p
	K int      // Barrett param, MUST satisfy K > L+32
	R *big.Int // R = 1<<K
}

// SecretKey: 숨은 링 키와 사설 다항식 f(x), h(x)
// f(x) = sum_{i=0..lambda} f_i x^i   ,  h(x) = sum_{i=0..lambda} h_i x^i
type SecretKey struct {
	R1, S1 *big.Int
	R2, S2 *big.Int
	FCoeffs []*big.Int // len=lambda+1
	HCoeffs []*big.Int // len=lambda+1
	Lambda  int
}

// PublicKey(DS용 검증키): Barrett 전개에 필요한 공개 요소 (p′, q′, μ, ν, s1, s2)
// - len(Pprime) = len(Qprime) = len(MuP) = len(MuQ) = (N+1)*M, where N = n+lambda
// - 인덱스: idx = i*M + j  (i in [0..N], j in [0..M-1])
type PublicKey struct {
	// Barrett-expanded public data
	S1p, S2p  *big.Int   // s1 = β*S1 mod p , s2 = β*S2 mod p
	Pprime    []*big.Int // p'_{ij} = β*P_{ij} mod p
	Qprime    []*big.Int // q'_{ij} = β*Q_{ij} mod p
	MuP       []*big.Int // μ_{ij} = floor(R * P_{ij} / S1)
	MuQ       []*big.Int // ν_{ij} = floor(R * Q_{ij} / S2)

	// dimensions
	N int // = n+lambda
	M int // number of noise variables u_j
	Lambda int
}
