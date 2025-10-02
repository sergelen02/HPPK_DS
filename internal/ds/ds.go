package ds

import (
	"errors"
	"math/big"
)

// 간단 헬스체크
func Hello() string { return "ds package is alive" }

// 1) 기본 파라미터( p=2^64-59, K=L+32 )로 키 생성
//    n,m,lambda는 실험/데모에 적당한 기본값(1,1,1)
func KeyGenDefault() (*Params, *SecretKey, *PublicKey, error) {
	pp := DefaultParams()
	sk, pk, err := KeyGen(pp, 1, 1, 1)
	if err != nil {
		return nil, nil, nil, err
	}
	return pp, sk, pk, nil
}

// 2) 파라미터를 넘겨받아 키 생성 (가장 일반적인 래퍼)
func KeyGenWith(pp *Params, n, m, lambda int) (*SecretKey, *PublicKey, error) {
	if pp == nil || pp.P == nil || pp.R == nil {
		return nil, nil, errors.New("KeyGenWith: nil or incomplete params")
	}
	return KeyGen(pp, n, m, lambda)
}

// 3) p, K를 직접 지정해 키 생성
func KeyGenFromPrime(p *big.Int, K int, n, m, lambda int) (*Params, *SecretKey, *PublicKey, error) {
	if p == nil || p.Sign() <= 0 {
		return nil, nil, nil, errors.New("KeyGenFromPrime: invalid p")
	}
	L := p.BitLen()
	if K < L+32 { // Barrett 안정성 권장선
		K = L + 32
	}
	pp := &Params{
		P: new(big.Int).Set(p),
		L: L,
		K: K,
		R: new(big.Int).Lsh(big.NewInt(1), uint(K)),
	}
	sk, pk, err := KeyGen(pp, n, m, lambda)
	if err != nil {
		return nil, nil, nil, err
	}
	return pp, sk, pk, nil
}

// 4) 서명 래퍼: (sig, x) 반환 (x = H(msg) mod p)
func SignMessage(pp *Params, sk *SecretKey, msg []byte) (*Signature, *big.Int, error) {
	return Sign(pp, sk, msg)
}

// 5) 검증 래퍼
func VerifyMessage(pp *Params, pk *PublicKey, sig *Signature, msg []byte) bool {
	return Verify(pp, pk, sig, msg)
}
