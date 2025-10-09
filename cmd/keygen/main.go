// cmd/keygen/main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	io "github.com/sergelen02/HPPK_DS/internal/iohelper"
	"github.com/sergelen02/HPPK_DS/internal/ds"
)

// p가 이미 out 하위 경로면 다시 join하지 않음 (이중 접두어 방지)
func joinOut(out, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	p = filepath.Clean(p)
	out = filepath.Clean(out)
	if rel, err := filepath.Rel(out, p); err == nil && !strings.HasPrefix(rel, "..") {
		return p
	}
	return filepath.Join(out, p)
}

func main() {
	outDir := flag.String("out", "artifacts", "output directory")
	flag.Parse()

	// 출력 디렉터리 보장
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}

	// 키 생성
	pp := ds.DefaultParams()
	sk, pk, err := ds.KeyGen(pp, 2, 1, 1)
	if err != nil {
		log.Fatal(err)
	}

	// gob→base64 포맷으로 저장 (JSON 아님)
	paramsPath := joinOut(*outDir, "params.json")
	skPath := joinOut(*outDir, "sk.json")
	pkPath := joinOut(*outDir, "pk.json")

	if err := io.SaveParams(paramsPath, pp); err != nil { log.Fatal(err) }
	if err := io.SaveSecretKey(skPath, sk); err != nil { log.Fatal(err) }
	if err := io.SavePublicKey(pkPath, pk); err != nil { log.Fatal(err) }

	fmt.Println("wrote", paramsPath+",", skPath+",", pkPath)
}
