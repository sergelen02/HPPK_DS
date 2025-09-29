// internal/ds/verify.go
package ds

import "math/big"

// Sum_i U_i(H) x^i == Sum_i V_i(F) x^i (mod P)
// U_i(H)=H p′_i - s1 floor(H μ_i / 2^K),  V_i(F)=F q′_i - s2 floor(F ν_i / 2^K)
func Verify(pp *Params, pk *PublicKey, msg []byte, sig *Signature) bool {
	n := len(pk.Pprime)
	if n == 0 || n != len(pk.Qprime) || n != len(pk.Mu) || n != len(pk.Nu) {
		return false
	}

	// 1) 메시지 해시 → x, 2) R=2^K, 3) 누적 초기화
	x := hashToX(pp.P, msg)  // *big.Int
	R := pp.R()              // *big.Int

	LHS := big.NewInt(0)
	RHS := big.NewInt(0)

	// x^i를 증분 곱으로 계산: xi = x^0 (=1)부터 시작
	xi := big.NewInt(1)

	for i := 0; i < n; i++ {
		// U_i(H) = H*P'_i - s1 * floor(H*mu_i / 2^K)
		t1 := mulMod(sig.H, pk.Pprime[i], pp.P)
		floorU := barrettFloor(sig.H, pk.Mu[i], R, int(pp.K)) // barrettFloor가 4인자 버전이어야 함
		t2 := mulMod(pk.S1p, floorU, pp.P)
		Ui := subMod(t1, t2, pp.P)

		// V_i(F) = F*Q'_i - s2 * floor(F*nu_i / 2^K)
		s1 := mulMod(sig.F, pk.Qprime[i], pp.P)
		floorV := barrettFloor(sig.F, pk.Nu[i], R, int(pp.K))
		s2 := mulMod(pk.S2p, floorV, pp.P)
		Vi := subMod(s1, s2, pp.P)

		// 누적: x^i에 대해 U_i(H)*x^i, V_i(F)*x^i
		LHS = addMod(LHS, mulMod(Ui, xi, pp.P), pp.P)
		RHS = addMod(RHS, mulMod(Vi, xi, pp.P), pp.P)

		// 다음 i를 위해 xi ← xi * x (mod P)
		xi = mulMod(xi, x, pp.P)
	}

	return LHS.Cmp(RHS) == 0
}

func hashToX(int *big.Int, msg []byte) any {
	panic("unimplemented")
}
