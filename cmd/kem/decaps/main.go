// cmd/kem/decaps/main.go
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sergelen02/HPPK_DS/internal/kem"
)

func main() {
	outDir := flag.String("out", "artifacts", "output directory")
	skPath := flag.String("sk", "", "secret key JSON path")
	ctPath := flag.String("ct", "", "ciphertext input path")
	ssPath := flag.String("ss", "ss.dec.bin", "shared secret output path (file or relative to -out)")
	flag.Parse()

	if *skPath == "" || *ctPath == "" {
		fmt.Fprintln(os.Stderr, "decaps: -sk and -ct are required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil { fatal(err) }

	ss := normOut(*ssPath, *outDir)

	// 개인키 로드
	sk, err := kem.LoadSecretKey(*skPath) // 내부 패키지 로더 사용
	if err != nil { fatal(err) }

	// 암문 로드
	ct, err := os.ReadFile(*ctPath)
	if err != nil { fatal(err) }

	// KEM Decaps
	shared, err := kem.Decaps(sk, ct)
	if err != nil { fatal(err) }

	if err := os.WriteFile(ss, shared, 0o644); err != nil { fatal(err) }
	fmt.Printf("wrote %s\n", ss)
}

// p가 이미 out 하위 경로면 다시 join하지 않음
func normOut(p, out string) string {
    if filepath.IsAbs(p) { return p }
    p = filepath.Clean(p)
    out = filepath.Clean(out)
    if rel, err := filepath.Rel(out, p); err == nil && !strings.HasPrefix(rel, "..") {
        return p
    }
    return filepath.Join(out, p)

}
func fatal(err error) { fmt.Fprintln(os.Stderr, "decaps:", err); os.Exit(1) }
