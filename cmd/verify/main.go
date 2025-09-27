package main

import (
	"fmt"
	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
	sk, pk := ds.KeyGen(pp, 2)
	msg := []byte("hello-HPPK_DS")
	sig, _ := ds.Sign(pp, sk, msg)
	ok := ds.Verify(pp, pk, msg, sig)
	fmt.Println("verify:", ok)
}
