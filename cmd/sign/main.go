package main

import (
	"encoding/hex"
	"fmt"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
	sk, _ := ds.KeyGen(pp, 2)
	msg := []byte("hello")

	sig, err := ds.Sign(pp, sk, msg)
	if err != nil {
		panic(err)
	}
	fmt.Println("sig.F:", hex.EncodeToString(sig.F.Bytes()))
	fmt.Println("sig.H:", hex.EncodeToString(sig.H.Bytes()))
}
