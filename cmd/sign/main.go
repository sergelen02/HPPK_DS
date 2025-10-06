package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	// 단순화를 위해 여기선 다시 KeyGen; 파일에서 읽고 싶으면 out/*.json을 파싱하세요.
	pp := ds.DefaultParams()
	sk, _, err := ds.KeyGen(pp, 2, 1, 1)
	if err != nil { log.Fatal(err) }

	msg := []byte("hello-HPPK_DS")
	sig, _, err := ds.Sign(pp, sk, msg)
	if err != nil { log.Fatal(err) }

	_ = os.MkdirAll("out", 0o755)
	f, err := os.Create("out/sig.json"); if err != nil { log.Fatal(err) }
	defer f.Close()
	enc := json.NewEncoder(f); enc.SetIndent("", "  ")
	_ = enc.Encode(sig)

	fmt.Println("wrote out/sig.json")
}
