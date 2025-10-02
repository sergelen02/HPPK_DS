package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	// 1) 기본 파라미터로 빠르게
	pp, sk, pk, err := ds.KeyGenDefault()
	if err != nil { log.Fatal(err) }

	// 2) 필요하면 파라미터 조정
	// pp.WithK(pp.L + 64) // Barrett 여유 더 주고 싶을 때

	msg := []byte("hello-HPPK_DS")

	sig, _, err := ds.SignMessage(pp, sk, msg)
	if err != nil { log.Fatal(err) }

	ok := ds.VerifyMessage(pp, pk, sig, msg)
	fmt.Println("verify:", ok)

	fmt.Println("F:", hex.EncodeToString(sig.F.Bytes()))
	fmt.Println("H:", hex.EncodeToString(sig.H.Bytes()))
}
