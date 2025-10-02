ppackage main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()

	// KeyGen(pp, n, m, lambda) → (*SecretKey, *PublicKey, error)
	sk, pk, err := ds.KeyGen(pp, 2, 1, 1) // 예: n=2, m=1, λ=1
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello-HPPK_DS")

	// Sign(pp, sk, msg) → (*Signature, x, error)
	sig, _, err := ds.Sign(pp, sk, msg)
	if err != nil {
		log.Fatal(err)
	}

	// Verify(pp, pk, sig, msg)  ← 인자 순서 주의!
	ok := ds.Verify(pp, pk, sig, msg)
	fmt.Println("verify:", ok)

	// 디버깅용 출력
	fmt.Println("F:", hex.EncodeToString(sig.F.Bytes()))
	fmt.Println("H:", hex.EncodeToString(sig.H.Bytes()))
}

