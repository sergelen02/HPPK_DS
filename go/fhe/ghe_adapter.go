package fhe

import "math/big"

// Adapter는 실제 라이브러리(HPPK의 Enc/Dec/Add/Mul)를 연결하는 훅입니다.
// 사용자는 이 인터페이스를 구현해 연결하세요.
// 예: xtaci/hppk 또는 내부 C/Go 라이브러리 래퍼.

type Adapter interface {
	// 키 생성 (있다면)
	KeyGen() (pk any, sk any, err error)

	// 암호화/복호화: 평문은 big.Int 또는 []byte 중 하나를 채택
	Enc(pk any, m *big.Int) (ct any, err error)
	Dec(sk any, ct any) (*big.Int, error)

	// 동형 연산: 암호문 입력 → 암호문 출력
	Add(ct1, ct2 any) (any, error)
	Mul(ct1, ct2 any) (any, error)
}
