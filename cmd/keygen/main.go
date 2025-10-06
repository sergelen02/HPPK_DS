package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
	sk, pk, err := ds.KeyGen(pp, 2, 1, 1)
	if err != nil { log.Fatal(err) }

	_ = os.MkdirAll("out", 0o755)
	write := func(path string, v any) {
		f, err := os.Create(path); if err != nil { log.Fatal(err) }
		defer f.Close()
		enc := json.NewEncoder(f); enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil { log.Fatal(err) }
	}
	write("out/params.json", pp)
	write("out/sk.json", sk)
	write("out/pk.json", pk)

	fmt.Println("wrote out/params.json, out/sk.json, out/pk.json")
}

