package main

import (
	"encoding/hex"
	"fmt"
	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
	sk, pk := ds.KeyGen(pp, 2) // n=2 예시
	fmt.Println("SK.F0:", hex.EncodeToString(sk.F0.Bytes()))
	fmt.Println("PK.s1:", hex.EncodeToString(pk.S1p.Bytes()))
}
