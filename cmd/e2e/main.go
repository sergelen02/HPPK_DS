package e2e

import (
	"fmt"
	"log"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
	sk, pk, err := ds.KeyGen(pp, 2, 1, 1) // n=2, m=1, λ=1
	if err != nil { log.Fatal(err) }

	msg := []byte("hello-HPPK_DS")
	sig, _, err := ds.Sign(pp, sk, msg)
	if err != nil { log.Fatal(err) }

	ok := ds.Verify(pp, pk, sig, msg)
	fmt.Println("verify:", ok) // true면 정상
}
