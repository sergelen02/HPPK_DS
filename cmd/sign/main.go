package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

// p가 이미 out 하위면 다시 join하지 않음 (artifacts/artifacts/… 방지)
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


func mustWriteJSON(path string, v any) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}

func mustReadFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// ★ 포인터 반환 (DefaultParams가 *ds.Params를 돌려주므로 시그니처를 *로)
func loadParams(path string) *ds.Params {
	if path == "" {
		return ds.DefaultParams()
	}
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var pp ds.Params
	if err := json.NewDecoder(f).Decode(&pp); err != nil {
		log.Fatal(err)
	}
	return &pp
}

// ★ 포인터 반환
func loadSecretKey(path string) *ds.SecretKey {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var sk ds.SecretKey
	if err := json.NewDecoder(f).Decode(&sk); err != nil {
		log.Fatal(err)
	}
	return &sk
}

func main() {
	outDir := flag.String("out", "artifacts", "output directory")
	skPath := flag.String("sk", "", "secret key JSON path")
	inPath := flag.String("in", "", "message file to sign")
	sigName := flag.String("sig", "sig.json", "signature output file name or path (relative to -out)")
	paramsPath := flag.String("params", "", "params JSON path (optional; default uses ds.DefaultParams)")
	pkPath := flag.String("pk", "", "public key JSON (optional, for self-verify)")
	flag.Parse()

	if *inPath == "" {
		log.Fatal("sign: -in is required")
	}
	if *skPath == "" {
		log.Fatal("sign: -sk is required (use keygen first)")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}

	// 로드 (모두 포인터여야 함)
	pp := loadParams(*paramsPath)  // *ds.Params
	sk := loadSecretKey(*skPath)   // *ds.SecretKey
	msg := mustReadFile(*inPath)

	// 서명 (포인터 인자 필요)
	sig, _, err := ds.Sign(pp, sk, msg)
	if err != nil {
		log.Fatal(err)
	}
	if *pkPath != "" {
        f, err := os.Open(*pkPath); if err != nil { log.Fatal(err) }
        defer f.Close()
        var pk ds.PublicKey
        if err := json.NewDecoder(f).Decode(&pk); err != nil { log.Fatal(err) }
        ok := ds.Verify(pp, &pk, sig, msg)
        fmt.Println("self-verify:", ok)
    }

	// 저장
	sigPath := joinOut(*outDir, *sigName)
	mustWriteJSON(sigPath, sig)
	fmt.Println("wrote", sigPath)
}

