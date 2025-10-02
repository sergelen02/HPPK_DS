package ds

import "math/big"

// Verify: Barrett 전개 Uij(H), Vij(F)로 ΣΣ 비교 (mod p)
// Uij(H) = H*p'_{ij} - s1 * floor(H*μ_{ij} / R)   (mod p)
// Vij(F) = F*q'_{ij} - s2 * floor(F*ν_{ij} / R)   (mod p)
func Verify(pp *Params, pk *PublicKey, sig *Signature, msg []byte) bool {
	if pp == nil || pk == nil || sig == nil || pp.P == nil || pp.R == nil {
		return false
	}
	p := pp.P
	K := uint(pp.K)

	// x, deterministic u_j from x (검증 결정성)
	x := hashToX(p, msg)
	u := deriveNoises(p, x, pk.M)

	// x^i 캐시
	xp := powCache(x, pk.N, p)

	left := new(big.Int)  // ΣΣ V(F)*x^i*u_j
	right := new(big.Int) // ΣΣ U(H)*x^i*u_j

	for i := 0; i <= pk.N; i++ {
		for j := 0; j < pk.M; j++ {
			k := idxIJ(i, j, pk.M)

			// floor((F*muQ)/R) == (F*muQ) >> K
			tL := new(big.Int).Mul(sig.F, pk.MuQ[k])
			tL.Rsh(tL, K) // >>K
			// coefL = F*q' - s2*floor(...)
			coefL := modMul(sig.F, pk.Qprime[k], p)
			coefL = modSub(coefL, modMul(pk.S2p, tL, p), p)

			// floor((H*muP)/R)
			tR := new(big.Int).Mul(sig.H, pk.MuP[k])
			tR.Rsh(tR, K)
			// coefR = H*p' - s1*floor(...)
			coefR := modMul(sig.H, pk.Pprime[k], p)
			coefR = modSub(coefR, modMul(pk.S1p, tR, p), p)

			// accumulate
			termL := modMul(coefL, xp[i], p)
			termL = modMul(termL, u[j], p)
			left = modAdd(left, termL, p)

			termR := modMul(coefR, xp[i], p)
			termR = modMul(termR, u[j], p)
			right = modAdd(right, termR, p)
		}
	}
	// equal mod p ?
	left.Mod(left, p)
	right.Mod(right, p)
	return left.Cmp(right) == 0
}
