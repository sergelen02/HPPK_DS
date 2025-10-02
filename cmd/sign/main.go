package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()

	// n=2, m=1, lambda=1 예시
	sk, pk, err := ds.KeyGen(pp, 2, 1, 1)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello")

	// Sign은 (sig, x, err) 반환 → x는 안 쓰면 _로 무시
	sig, _, err := ds.Sign(pp, sk, msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("sig.F:", hex.EncodeToString(sig.F.Bytes()))
	fmt.Println("sig.H:", hex.EncodeToString(sig.H.Bytes()))

	// 검증까지 확인
	ok := ds.Verify(pp, pk, sig, msg)
	fmt.Println("verify:", ok) // true 기대
}
