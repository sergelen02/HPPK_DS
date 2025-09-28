//go:build hppk_impl

package ds

import "math/big"
import "fmt"

// x = H(domain||msg) mod p  (해싱은 필요 시 추가)
func hashToX(p *big.Int, m []byte) *big.Int {
	// 데모: 바이트→정수 변환 후 mod p (실험에서는 SHA-256/Shake로 교체 권장)
	x := new(big.Int).SetBytes(m)
	return mod(x, p)
}

func evalLin(a0, a1, x, p *big.Int) *big.Int {
	t := new(big.Int).Mul(a1, x)
	t.Add(t, a0)
	return mod(t, p)
}

func mod(t *big.Int, p *big.Int) *big.Int {
	panic("unimplemented")
}

// F=(f(x)*R2^{-1}) mod S2, H=(h(x)*R1^{-1}) mod S1
func Sign(pp *Params, sk *SecretKey, msg []byte) (*Signature, error) {
	x := hashToX(pp.P, msg)
	fx := evalLin(sk.F0, sk.F1, x, pp.P)
	hx := evalLin(sk.H0, sk.H1, x, pp.P)

	r2Inv := invMod(sk.R2, sk.S2)
	if r2Inv == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoInverse, "R2,S2")
	}
	r1Inv := invMod(sk.R1, sk.S1)
	if r1Inv == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoInverse, "R1,S1")
	}

	F := mulMod(mod(fx, sk.S2), r2Inv, sk.S2)
	H := mulMod(mod(hx, sk.S1), r1Inv, sk.S1)
	return &Signature{F: F, H: H}, nil
}
