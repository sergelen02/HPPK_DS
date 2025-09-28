package ds

import (
	"crypto/rand"
	"math/big"
)

// 샘플러들 (실험용)
func randMod(m *big.Int) *big.Int {
	x, _ := rand.Int(rand.Reader, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}
	return x
}
func coprime(a, b *big.Int) bool {
	g := new(big.Int).GCD(nil, nil, a, b)
	return g.Cmp(big.NewInt(1)) == 0
}

// Placeholder: 공개다항 P(x),Q(x) 계수(길이 n)를 외부에서 공급하거나 여기서 생성
func makePQ(n int, p *big.Int) (P, Q []*big.Int) {
	P = make([]*big.Int, n)
	Q = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		P[i] = randMod(p)
		Q[i] = randMod(p)
	}
	return
}

// Barrett 상수 μ,ν 계산(스켈레톤): 실제론 P,Q, S1,S2에 맞춘 전처리 필요
func computeMuNu(pp *Params, P, Q []*big.Int) (mu, nu []*big.Int) {
	n := len(P)
	mu = make([]*big.Int, n)
	nu = make([]*big.Int, n)
	R := pp.R()
	for i := 0; i < n; i++ {
		mu[i] = new(big.Int).Rsh(R, 2)
		nu[i] = new(big.Int).Rsh(R, 3)
	} // TODO: 실제 값으로 교체
	return
}

// Algorithm 4: DS KeyGen → (SK, PK)
func KeyGen(pp *Params, n int) (*SecretKey, *PublicKey) {
	p := pp.P
	// 1) f(x), h(x) 계수
	f0, f1 := randMod(p), randMod(p)
	h0, h1 := randMod(p), randMod(p)
	// 2) (R1,S1),(R2,S2), gcd=1
	var R1, S1, R2, S2 *big.Int
	for {
		R1, S1 = randMod(p), randMod(p)
		if S1.Sign() == 0 {
			S1 = big.NewInt(1)
		}
		if coprime(R1, S1) {
			break
		}
	}
	for {
		R2, S2 = randMod(p), randMod(p)
		if S2.Sign() == 0 {
			S2 = big.NewInt(1)
		}
		if coprime(R2, S2) {
			break
		}
	}
	// 3) β
	beta := randMod(p)

	// 공개다항 P,Q 계수
	Pc, Qc := makePQ(n, p)

	// Barrett 계수 μ,ν
	mu, nu := computeMuNu(pp, Pc, Qc)

	// p′ = β·P, q′ = β·Q, s1 = β·S1, s2 = β·S2  (mod p)
	pprime := make([]*big.Int, n)
	qprime := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		pprime[i] = mulMod(beta, Pc[i], p)
		qprime[i] = mulMod(beta, Qc[i], p)
	}
	s1p := mulMod(beta, S1, p)
	s2p := mulMod(beta, S2, p)

	sk := &SecretKey{F0: f0, F1: f1, H0: h0, H1: h1, R1: R1, S1: S1, R2: R2, S2: S2, Beta: beta}
	pk := &PublicKey{Pprime: pprime, Qprime: qprime, Mu: mu, Nu: nu, S1p: s1p, S2p: s2p}
	return sk, pk
}
