package ds

import (
	"errors"
	"fmt"
	"math/big"
)

// f(x), h(x) 평가 (mod P) → F = f(x)*R2^{-1} (mod S2), H = h(x)*R1^{-1} (mod S1)
type Signature struct{ F, H *big.Int }

func Sign(pp *Params, sk *SecretKey, msg []byte) (*Signature, *big.Int, error) {
	// --- 입력 검증 ---
	if pp == nil {
		return nil, nil, errors.New("nil params")
	}
	if pp.P == nil {
		return nil, nil, errors.New("nil params.P (rehydrate or load correctly)")
	}
	if sk == nil {
		return nil, nil, errors.New("nil secret key")
	}
	// 필수 모듈러 파라미터 확인
	if sk.R1 == nil { return nil, nil, fmt.Errorf("secret key R1 is nil (rehydrate/load)") }
	if sk.S1 == nil { return nil, nil, fmt.Errorf("secret key S1 is nil (rehydrate/load)") }
	if sk.R2 == nil { return nil, nil, fmt.Errorf("secret key R2 is nil (rehydrate/load)") }
	if sk.S2 == nil { return nil, nil, fmt.Errorf("secret key S2 is nil (rehydrate/load)") }

	// 다항 계수 확인 (nil 원소가 있으면 곧바로 실패시켜 추적하기 쉽게)
	for i, c := range sk.FCoeffs {
		if c == nil { return nil, nil, fmt.Errorf("FCoeffs[%d] is nil (rehydrate/load)", i) }
	}
	for i, c := range sk.HCoeffs {
		if c == nil { return nil, nil, fmt.Errorf("HCoeffs[%d] is nil (rehydrate/load)", i) }
	}

	// --- 본 연산 ---
	x := hashToX(pp.P, msg) // 내부에서 mod P 보장되면 ok; 아니라면 아래 한 줄 추가
	// x.Mod(x, pp.P)

	// 역원 계산: 피연산자 nil 방지 & 역원 없음(nil 반환) 체크
	r2Inv := new(big.Int).ModInverse(sk.R2, sk.S2)
	if r2Inv == nil {
		return nil, nil, errors.New("R2 has no inverse modulo S2")
	}
	r1Inv := new(big.Int).ModInverse(sk.R1, sk.S1)
	if r1Inv == nil {
		return nil, nil, errors.New("R1 has no inverse modulo S1")
	}

	fx := evalPoly(sk.FCoeffs, x, pp.P)
	hx := evalPoly(sk.HCoeffs, x, pp.P)

	F := new(big.Int).Mul(fx, r2Inv)
	F.Mod(F, sk.S2)

	H := new(big.Int).Mul(hx, r1Inv)
	H.Mod(H, sk.S1)

	return &Signature{F: F, H: H}, x, nil
}
