package ds

import "math/big"

type Params struct {
	P *big.Int // prime modulus
	K int      // Barrett exponent; R=2^K
	N int      // P,Q 계수 길이
    Seed []byte// 테스트 재현용
}

func FromPaper() *Params {
    return &Params{
        P:    mustBig("FFFFFFFFFFFFFFC5", 16), // 예시(논문값으로 교체)
        K:    208,
        N:    2,
        Seed: mustHex("c0ffee00c0ffee00c0ffee00c0ffee00"),
    }
}

func mustHex(s string) {
	panic("unimplemented")
}

func mustBig(s string, i int) {
	panic("unimplemented")
}
