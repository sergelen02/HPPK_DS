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
	// x는 메시지에서 단 한 번만 해시
	x := hashToX(pp.P, msg)
	R := pp.R()

	LHS := big.NewInt(0)
	RHS := big.NewInt(0)

	for i := 0; i < n; i++ {
		// U_i(H)
		t1 := mulMod(sig.H, pk.Pprime[i], pp.P)
		floor := barrettFloor(sig.H, pk.Mu[i], int(pp.K)) // <- K 인자 없는 버전 사용 중
		t2 := mulMod(pk.S1p, floor, pp.P)
		Ui := subMod(t1, t2, pp.P)

		// V_i(F)
		s1 := mulMod(sig.F, pk.Qprime[i], pp.P)
		floorV := barrettFloor(sig.F, pk.Nu[i], int(pp.K))
		s2 := mulMod(pk.S2p, floorV, pp.P)
		Vi := subMod(s1, s2, pp.P)

		// 누적: 매 i마다 xi를 한 번만 계산
		xi := powModInt(x, i, pp.P) // 또는: expMod(x, i, pp.P)
		LHS = addMod(LHS, mulMod(Ui, xi, pp.P), pp.P)
		RHS = addMod(RHS, mulMod(Vi, xi, pp.P), pp.P)
	}
	return LHS.Cmp(RHS) == 0
}

func powModInt(x any, i int, int *big.Int) any {
	panic("unimplemented")
}

func hashToX(int *big.Int, msg []byte) any {
	panic("unimplemented")
}
