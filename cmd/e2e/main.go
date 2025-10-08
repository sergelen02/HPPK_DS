
// cmd/e2e/main.go
package main

import (
	"fmt"
	"log"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()               // *ds.Params
	sk, pk, err := ds.KeyGen(pp, 2, 1, 1)  // (*ds.SecretKey, *ds.PublicKey, error)
	if err != nil { log.Fatal(err) }

	msg := []byte("hello-HPPK_DS")
	sig, _, err := ds.Sign(pp, sk, msg)    // (*ds.Params, *ds.SecretKey, []byte)
	if err != nil { log.Fatal(err) }

	ok := ds.Verify(pp, pk, sig, msg)      // (*ds.Params, *ds.PublicKey, Signature, []byte)
	fmt.Println("verify:", ok)             // true면 정상
}
