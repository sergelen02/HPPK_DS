package ds

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// --- 유틸: 레포 내 mathutil.go와 동일 시그니처를 가정 ---
// mulMod(a,b,m) *big.Int
// invMod(a,m) *big.Int // 역원 없으면 nil
// addMod/subMod 등은 여기서 사용하지 않음

// hashToX: x = H(msg) mod P  (도메인 구분자는 필요시 바깥에서 prefix해서 넘겨주세요)
func hashToX(P *big.Int, msg []byte) *big.Int {
	h := sha256.Sum256(msg)
	x := new(big.Int).SetBytes(h[:])
	x.Mod(x, P)
	if x.Sign() == 0 {
		x.SetInt64(1) // x=0 회피(일부 파라미터에서 검증식이 휘청일 수 있음)
	}
	return x
}

// evalLin: a1*x + a0 (mod p)
func evalLin(a0, a1, x, p *big.Int) *big.Int {
	t := new(big.Int).Mul(a1, x) // a1*x
	t.Add(t, a0)                 // + a0
	t.Mod(t, p)                  // mod p
	return t
}

// Sign
// 가정:
//   - pp.P : 큰 소수 모듈러
//   - sk.(R1,S1), (R2,S2) : 서로소(역원 존재), f/h는 1차 (F1,F0/H1,H0)
//   - Verify는 U_i(H), V_i(F) 정의로 검증 (당신이 올린 verify.go 형태)
//   - alpha/beta 스케일이 논문에 있을 수 있으나, 현 Verify가 직접 참조하지 않으므로 생략
//     (논문이 alpha/beta를 요구한다면, 여기에 곱해서 F,H를 스케일하거나 Signature에 포함 후 Verify도 일치시켜야 함)
func Sign(pp *Params, sk *SecretKey, msg []byte) (*Signature, error) {
	// 기본 유효성
	if pp == nil || pp.P == nil || sk == nil ||
		sk.R1 == nil || sk.S1 == nil || sk.R2 == nil || sk.S2 == nil ||
		sk.F0 == nil || sk.F1 == nil || sk.H0 == nil || sk.H1 == nil {
		return nil, fmt.Errorf("nil parameter in Sign")
	}

	// 1) 메시지 → 정수 x (mod P)
	x := hashToX(pp.P, msg)

	// 2) f(x), h(x) 평가 (mod P)
	fx := evalLin(sk.F0, sk.F1, x, pp.P)
	hx := evalLin(sk.H0, sk.H1, x, pp.P)

	// 3) 역원 계산: R2^{-1} mod S2, R1^{-1} mod S1
	r2Inv := new(big.Int).ModInverse(sk.R2, sk.S2)
	if r2Inv == nil {
		return nil, fmt.Errorf("%w: R2,S2", ErrNoInverse)
	}
	r1Inv := new(big.Int).ModInverse(sk.R1, sk.S1)
	if r1Inv == nil {
		return nil, fmt.Errorf("%w: R1,S1", ErrNoInverse)
	}

	// 4) F = (fx * R2^{-1}) mod S2, H = (hx * R1^{-1}) mod S1
	//    fx/hx는 현재 P-모듈러지만, S-모듈러로 다시 줄여 곱해도 동치
	F := mulMod(new(big.Int).Mod(fx, sk.S2), r2Inv, sk.S2)
	H := mulMod(new(big.Int).Mod(hx, sk.S1), r1Inv, sk.S1)

	// 5) 서명 생성 (현 Verify는 F,H만 사용)
	return &Signature{F: F, H: H}, nil
}
