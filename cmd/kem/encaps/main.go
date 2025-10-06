// cmd/kem/encaps/main.go
package main

import (
	"bytes"
	"fmt"
	"log"

	ds "github.com/sergelen02/HPPK_DS/internal/ds"
	hppk "github.com/sergelen02/HPPK_DS/go/KEM/HPPK
)

func main() {
	pp := ds.DefaultParams()

	// 예시 파라미터: n=2, m=2, lambda=1
	sk, pk, err := hppk.KeyGen(pp, 2, 2, 1)
	if err != nil {
		log.Fatal(err)
	}

	ct, ss1, err := hppk.Encaps(pp, pk)
	if err != nil {
		log.Fatal(err)
	}

	ss2, err := hppk.Decaps(pp, sk, ct)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("KEM shared equal:", bytes.Equal(ss1, ss2))
}
