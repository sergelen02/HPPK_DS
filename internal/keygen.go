package ds

import (
	"crypto/rand"
	"math/big"
)

// --- 헬퍼 (이미 있다면 중복 정의 제거하세요) ---

// m 모듈러 균등분포 난수
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

// 모듈러 연산 (이미 math.go 등에 있다면 삭제)
func mod(a, m *big.Int) *big.Int {
	x := new(big.Int).Mod(a, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}
	return x
}

func mulMod(a, b, m *big.Int) *big.Int {
	t := new(big.Int).Mul(a, b)
	return mod(t, m)
}

// 공개다항 P(x), Q(x) 계수 생성 (실험용)
// TODO: 논문 벡터/절차로 결정적 생성 또는 부록값 로드 권장
func makePQ(n int, p *big.Int) (P, Q []*big.Int) {
	P = make([]*big.Int, n)
	Q = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		P[i] = randMod(p)
		Q[i] = randMod(p)
	}
	return
}

// --- 핵심: 논문 Algorithm 4에 따른 Barrett 상수 ---

// R = 2^K, μ_i = floor(R * P_i / S1),  ν_i = floor(R * Q_i / S2)
func computeMuNu(pp *Params, P, Q []*big.Int, S1, S2 *big.Int) (mu, nu []*big.Int) {
	if len(P) != len(Q) {
		panic("computeMuNu: P,Q length mismatch")
	}
	if S1.Sign() == 0 || S2.Sign() == 0 {
		panic("computeMuNu: S1 or S2 is zero")
	}
	R := pp.R()

	n := len(P)
	mu = make([]*big.Int, n)
	nu = make([]*big.Int, n)

	for i := 0; i < n; i++ {
		// μ_i
		t := new(big.Int).Mul(R, P[i])
		t.Div(t, S1) // floor
		mu[i] = t

		// ν_i
		u := new(big.Int).Mul(R, Q[i])
		u.Div(u, S2) // floor
		nu[i] = u
	}
	return
}

// --- Algorithm 4: DS KeyGen → (SK, PK) ---

func KeyGen(pp *Params, n int) (*SecretKey, *PublicKey) {
	p := pp.P
	if n <= 0 {
		n = 2 // TODO: 프로젝트 기본 차수/계수 길이
	}

	// 1) f(x)=f0+f1x, h(x)=h0+h1x (계수는 mod p)
	f0, f1 := randMod(p), randMod(p)
	h0, h1 := randMod(p), randMod(p)

	// 2) (R1,S1), (R2,S2) with gcd=1
	var R1, S1, R2, S2 *big.Int
	for {
		R1, S1 = randMod(p), randMod(p)
		if S1.Sign() == 0 {
			S1 = big.NewInt(1) // zero guard
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

	// 4) 공개 다항 P,Q 계수
	Pc, Qc := makePQ(n, p)

	// 5) Barrett 계수 μ,ν  (S1,S2 필요)
	mu, nu := computeMuNu(pp, Pc, Qc, S1, S2)

	// 6) p′ = β·P, q′ = β·Q, s1 = β·S1, s2 = β·S2  (mod p)
	pprime := make([]*big.Int, n)
	qprime := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		pprime[i] = mulMod(beta, Pc[i], p)
		qprime[i] = mulMod(beta, Qc[i], p)
	}
	s1p := mulMod(beta, S1, p)
	s2p := mulMod(beta, S2, p)

	// 7) 결과
	sk := &SecretKey{
		F0: f0, F1: f1,
		H0: h0, H1: h1,
		R1: R1, S1: S1,
		R2: R2, S2: S2,
		Beta: beta,
	}
	pk := &PublicKey{
		Pprime: pprime,
		Qprime: qprime,
		Mu:     mu,
		Nu:     nu,
		S1p:    s1p,
		S2p:    s2p,
	}
	return sk, pk
}
