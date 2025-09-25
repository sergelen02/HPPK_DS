package main

import (
	"encoding/hex"
	"fmt"
	"github.com/sergelen02/HPPK_DS/internal/ds"
	"math/big"
)

func main() {
	pp := ds.DefaultParams()
	sk, _ := ds.KeyGen(pp, 2)
	msg := []byte("hello-HPPK_DS")
	sig, _ := ds.Sign(pp, sk, msg)
	fmt.Println("F:", hex.EncodeToString(sig.F.Bytes()))
	fmt.Println("H:", hex.EncodeToString(sig.H.Bytes()))
	_ = new(big.Int) // keep imports happy if needed
}
