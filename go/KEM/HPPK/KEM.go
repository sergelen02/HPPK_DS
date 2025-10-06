// 파일: internal/kem/hppk/kem.go
package hppk

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	ds "github.com/sergelen02/HPPK_DS/internal/ds"
)

// ===== 키 구조 =====
type PublicKey struct {
	// 숨은 링에서 암호화된 계수 (평탄화: idx = i*M + j, i=0..N, j=0..M-1)
	Pij []*big.Int // P_ij = R1 * p_ij mod S1
	Qij []*big.Int // Q_ij = R2 * q_ij mod S2
	N, M int       // 다항 차수 상한 N(=n+lambda), 잡음 변수 수 M
}

type SecretKey struct {
	R1, S1 *big.Int
	R2, S2 *big.Int
	FCoeffs, HCoeffs []*big.Int // f,h 계수 (길이 lambda+1)
	Lambda int
}

type Ciphertext struct {
	P *big.Int // Σ P_ij * (x^i u_j mod p)
	Q *big.Int // Σ Q_ij * (x^i u_j mod p)
}

// ===== 유틸 =====
func idxIJ(i, j, M int) int { return i*M + j }

func randZp(p *big.Int) (*big.Int, error) {
	for {
		z, err := rand.Int(rand.Reader, p)
		if err != nil { return nil, err }
		if z.Sign() != 0 { return z, nil }
	}
}
func randOddLbits(L int) (*big.Int, error) {
	bytes := (L + 7) / 8
	buf := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil { return nil, err }
	buf[0] |= 0x80
	buf[len(buf)-1] |= 1
	return new(big.Int).SetBytes(buf), nil
}
func randCoprimePair(L int) (*big.Int, *big.Int, error) {
	for {
		S, err := randOddLbits(L); if err != nil { return nil, nil, err }
		R, err := randOddLbits(L); if err != nil { return nil, nil, err }
		if new(big.Int).GCD(nil, nil, R, S).Cmp(big.NewInt(1)) == 0 {
			return R, S, nil
		}
	}
}
func powCache(x *big.Int, N int, p *big.Int) []*big.Int {
	out := make([]*big.Int, N+1)
	out[0] = new(big.Int).SetInt64(1)
	for i := 1; i <= N; i++ {
		out[i] = new(big.Int).Mul(out[i-1], x)
		out[i].Mod(out[i], p)
	}
	return out
}

// ===== KeyGen (KEM용) =====
// 논문: 공개키는 P_ij, Q_ij (숨은 링 암호화 계수), 개인키는 (R1,S1),(R2,S2), f,h  :contentReference[oaicite:11]{index=11} :contentReference[oaicite:12]{index=12}
func KeyGen(pp *ds.Params, n, m, lambda int) (*SecretKey, *PublicKey, error) {
	if pp == nil || pp.P == nil { return nil, nil, errors.New("nil params") }
	if lambda < 1 { lambda = 1 }
	if n < 1 { n = 1 }
	if m < 1 { m = 1 }
	N := n + lambda

	// 숨은 링 키
	R1, S1, err := randCoprimePair(pp.L)
	if err != nil { return nil, nil, err }
	R2, S2, err := randCoprimePair(pp.L)
	if err != nil { return nil, nil, err }

	// f,h 계수
	fc := make([]*big.Int, lambda+1)
	hc := make([]*big.Int, lambda+1)
	for i := 0; i <= lambda; i++ {
		if fc[i], err = randZp(pp.P); err != nil { return nil, nil, err }
		if hc[i], err = randZp(pp.P); err != nil { return nil, nil, err }
	}

	// p_ij, q_ij = (f*b_j)_i, (h*b_j)_i  (b_j는 각각 난수 다항식)
	pcoef := make([]*big.Int, (N+1)*m)
	qcoef := make([]*big.Int, (N+1)*m)
	for j := 0; j < m; j++ {
		b := make([]*big.Int, n+1)
		for t := 0; t <= n; t++ { b[t], _ = randZp(pp.P) }
		for i := 0; i <= N; i++ {
			accP := new(big.Int); accQ := new(big.Int)
			for t := 0; t <= i; t++ {
				if t <= lambda && (i-t) <= n {
					tmpP := new(big.Int).Mul(fc[t], b[i-t]); tmpP.Mod(tmpP, pp.P)
					tmpQ := new(big.Int).Mul(hc[t], b[i-t]); tmpQ.Mod(tmpQ, pp.P)
					accP.Add(accP, tmpP).Mod(accP, pp.P)
					accQ.Add(accQ, tmpQ).Mod(accQ, pp.P)
				}
			}
			pcoef[idxIJ(i,j,m)] = accP
			qcoef[idxIJ(i,j,m)] = accQ
		}
	}

	// 숨은 링 암호화 계수: P_ij = R1*p_ij mod S1, Q_ij = R2*q_ij mod S2  :contentReference[oaicite:13]{index=13}
	Pij := make([]*big.Int, (N+1)*m)
	Qij := make([]*big.Int, (N+1)*m)
	for i := 0; i <= N; i++ {
		for j := 0; j < m; j++ {
			k := idxIJ(i,j,m)
			Pij[k] = new(big.Int).Mul(R1, pcoef[k]); Pij[k].Mod(Pij[k], S1)
			Qij[k] = new(big.Int).Mul(R2, qcoef[k]); Qij[k].Mod(Qij[k], S2)
		}
	}

	sk := &SecretKey{ R1:R1, S1:S1, R2:R2, S2:S2, FCoeffs:fc, HCoeffs:hc, Lambda:lambda }
	pk := &PublicKey{ Pij:Pij, Qij:Qij, N:N, M:m }
	return sk, pk, nil
}

// ===== Encaps =====
// x ← F_p 무작위, u_j ← F_p 무작위.  P = Σ P_ij * (x^i u_j mod p), Q = Σ Q_ij * (x^i u_j mod p)  → C=(P,Q)
// 공유키 ss = SHA256(x)  (KDF는 필요에 맞게 바꾸세요)  :contentReference[oaicite:14]{index=14} :contentReference[oaicite:15]{index=15}
func Encaps(pp *ds.Params, pk *PublicKey) (*Ciphertext, []byte, error) {
	if pp == nil || pk == nil { return nil, nil, errors.New("nil input") }

	x, err := randZp(pp.P); if err != nil { return nil, nil, err }
	// u_j
	u := make([]*big.Int, pk.M)
	for j := 0; j < pk.M; j++ { u[j], _ = randZp(pp.P) }

	xp := powCache(x, pk.N, pp.P)
	Psum := new(big.Int); Qsum := new(big.Int)

	for i := 0; i <= pk.N; i++ {
		for j := 0; j < pk.M; j++ {
			k := idxIJ(i,j,pk.M)
			xij := new(big.Int).Mul(xp[i], u[j]); xij.Mod(xij, pp.P) // x^i * u_j mod p
			// P += P_ij * xij  (여기서는 S1로 줄이지 않아도 됨; 수신자가 mod S1을 적용)  :contentReference[oaicite:16]{index=16}
			tmp := new(big.Int).Mul(pk.Pij[k], xij); Psum.Add(Psum, tmp)
			tmp2:= new(big.Int).Mul(pk.Qij[k], xij); Qsum.Add(Qsum, tmp2)
		}
	}
	ct := &Ciphertext{ P:Psum, Q:Qsum }

	// 공유키: ss = KDF(x)
	xb := x.Bytes()
	ss := sha256.Sum256(xb)
	return ct, ss[:], nil
}

// ===== Decaps =====
// p̂ = (P * R1^{-1} mod S1) mod p,    q̂ = (Q * R2^{-1} mod S2) mod p
// k = p̂ * (q̂^{-1} mod p) mod p
// λ=1이면  x = (f0 - k h0) * (k h1 - f1)^{-1} mod p  로 바로 복원 → ss = KDF(x)  :contentReference[oaicite:17]{index=17} :contentReference[oaicite:18]{index=18}
func Decaps(pp *ds.Params, sk *SecretKey, ct *Ciphertext) ([]byte, error) {
	if pp == nil || sk == nil || ct == nil { return nil, errors.New("nil input") }
	if sk.Lambda != 1 { return nil, errors.New("only lambda=1 supported in this demo") }

	// R^{-1} mod S
	r1Inv := new(big.Int).ModInverse(sk.R1, sk.S1)
	r2Inv := new(big.Int).ModInverse(sk.R2, sk.S2)
	if r1Inv == nil || r2Inv == nil { return nil, errors.New("no inverse for R mod S") }

	// p̂, q̂
	ph := new(big.Int).Mul(ct.P, r1Inv); ph.Mod(ph, sk.S1); ph.Mod(ph, pp.P)
	qh := new(big.Int).Mul(ct.Q, r2Inv); qh.Mod(qh, sk.S2); qh.Mod(qh, pp.P)

	// k = p̂ / q̂ mod p
	qhInv := new(big.Int).ModInverse(qh, pp.P)
	if qhInv == nil { return nil, errors.New("qhat not invertible mod p") }
	k := new(big.Int).Mul(ph, qhInv); k.Mod(k, pp.P)

	// lambda=1: f(x)=f0+f1 x, h(x)=h0+h1 x  →  f0+f1 x = k(h0+h1 x)
	f0, f1 := sk.FCoeffs[0], sk.FCoeffs[1]
	h0, h1 := sk.HCoeffs[0], sk.HCoeffs[1]

	num := new(big.Int).Sub(f0, new(big.Int).Mul(k, h0)); num.Mod(num, pp.P)
	den := new(big.Int).Sub(new(big.Int).Mul(k, h1), f1); den.Mod(den, pp.P)
	denInv := new(big.Int).ModInverse(den, pp.P)
	if denInv == nil { return nil, errors.New("denominator not invertible") }

	x := new(big.Int).Mul(num, denInv); x.Mod(x, pp.P)

	ss := sha256.Sum256(x.Bytes())
	return ss[:], nil
}
