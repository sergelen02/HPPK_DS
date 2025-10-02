package ds

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
)

// ---- mod 연산 ----
func modAdd(a, b, p *big.Int) *big.Int {
	z := new(big.Int).Add(a, b); z.Mod(z, p)
	if z.Sign() < 0 { z.Add(z, p) }
	return z
}
func modSub(a, b, p *big.Int) *big.Int {
	z := new(big.Int).Sub(a, b); z.Mod(z, p)
	if z.Sign() < 0 { z.Add(z, p) }
	return z
}
func modMul(a, b, p *big.Int) *big.Int {
	z := new(big.Int).Mul(a, b); z.Mod(z, p)
	if z.Sign() < 0 { z.Add(z, p) }
	return z
}

// ---- 인덱스/거듭제곱 캐시 ----
func idxIJ(i, j, M int) int { return i*M + j }

func powCache(x *big.Int, N int, p *big.Int) []*big.Int {
	out := make([]*big.Int, N+1)
	out[0] = new(big.Int).SetInt64(1)
	for i := 1; i <= N; i++ {
		out[i] = new(big.Int).Mul(out[i-1], x)
		out[i].Mod(out[i], p)
	}
	return out
}

// ---- hash→field & u-도출 ----
func hashToX(p *big.Int, msg []byte) *big.Int {
	sum := sha256.Sum256(msg)
	x := new(big.Int).SetBytes(sum[:])
	x.Mod(x, p)
	if x.Sign() < 0 { x.Add(x, p) }
	return x
}
func deriveNoises(p, x *big.Int, m int) []*big.Int {
	out := make([]*big.Int, m)
	xb := x.Bytes()
	for j := 0; j < m; j++ {
		h := sha256.Sum256(append(xb, byte(j+1)))
		u := new(big.Int).SetBytes(h[:])
		u.Mod(u, p)
		if u.Sign() == 0 { u.SetInt64(1) }
		out[j] = u
	}
	return out
}

// ---- 난수 ----
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
	buf[0] |= 0x80              // 상위비트
	buf[len(buf)-1] |= 0x01     // 홀수
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

// ---- 다항 평가 ----
func evalPoly(coeffs []*big.Int, x, p *big.Int) *big.Int {
	acc := new(big.Int).SetInt64(0)
	pow := new(big.Int).SetInt64(1)
	for i := 0; i < len(coeffs); i++ {
		term := modMul(coeffs[i], pow, p)
		acc = modAdd(acc, term, p)
		pow.Mul(pow, x).Mod(pow, p)
	}
	return acc
}
