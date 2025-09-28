package ds

import "math/big"

// Sum_i U_i(H) x^i == Sum_i V_i(F) x^i (mod P)
func Verify(pp *Params, pk *PublicKey, msg []byte, sig *Signature) bool {
	n := len(pk.Pprime)
	if n == 0 || n != len(pk.Qprime) || n != len(pk.Mu) || n != len(pk.Nu) {
		return false
	}

	// 메시지로부터 x 한 번 계산
	x := hashToX(pp.P, msg)
	R := pp.R()

	LHS := big.NewInt(0)
	RHS := big.NewInt(0)

	for i := 0; i < n; i++ {
		// U_i(H) = H*p'_i - s1*floor(H*μ_i/R)
		t1 := mulMod(sig.H, pk.Pprime[i], pp.P)
		floorU := barrettFloor(sig.H, pk.Mu[i], R, int(pp.K)) // 4-인자 버전 (x, mu, R, K)
		t2 := mulMod(pk.S1p, floorU, pp.P)
		Ui := subMod(t1, t2, pp.P)

		// V_i(F) = F*q'_i - s2*floor(F*ν_i/R)
		s1 := mulMod(sig.F, pk.Qprime[i], pp.P)
		floorV := barrettFloor(sig.F, pk.Nu[i], R, int(pp.K))
		s2 := mulMod(pk.S2p, floorV, pp.P)
		Vi := subMod(s1, s2, pp.P)

		// xi = x^i mod P
		xi := powModInt(x, i, pp.P) // 또는 expMod(x, i, pp.P)

		LHS = addMod(LHS, mulMod(Ui, xi, pp.P), pp.P)
		RHS = addMod(RHS, mulMod(Vi, xi, pp.P), pp.P)
	}
	return LHS.Cmp(RHS) == 0
}
