// cmd/verify/main.go
package main

import (
	"fmt"
	"log"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
    pp.WithK(208) // 필요하면 K 조정 (예: 208), 최소 L+32 이상으로 자동 보정됨
	sk, pk, err := ds.KeyGen(pp, 2, 1, 1)
	if err != nil { log.Fatal(err) }

	msg := []byte("hello-HPPK_DS")
	sig, _, err := ds.Sign(pp, sk, msg)
	if err != nil { log.Fatal(err) }

	ok := ds.Verify(pp, pk, sig, msg)
	fmt.Println("verify:", ok)
}
