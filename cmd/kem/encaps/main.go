// cmd/kem/encaps/main.go
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
	pkPath := flag.String("pk", "", "public key JSON path")
	ctPath := flag.String("ct", "ct.bin", "ciphertext output path (file or relative to -out)")
	ssPath := flag.String("ss", "ss.enc.bin", "shared secret output path (file or relative to -out)")
	flag.Parse()

	if *pkPath == "" {
		fmt.Fprintln(os.Stderr, "encaps: -pk is required (path to pk.json)")
		os.Exit(2)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	// 경로 정규화: 상대경로면 -out 하위에 저장
	ct := normOut(*ctPath, *outDir)
	ss := normOut(*ssPath, *outDir)

	// 공개키 로드
	pk, err := kem.LoadPublicKey(*pkPath) // 내부 패키지의 로더 사용 (없다면 프로젝트의 로더 함수명에 맞춰 수정)
	if err != nil { fatal(err) }

	// KEM Encaps
	ciphertext, shared, err := kem.Encaps(pk) // 내부 패키지 호출 (이름이 다르면 맞춰 수정)
	if err != nil { fatal(err) }

	// 파일 저장
	if err := os.WriteFile(ct, ciphertext, 0o644); err != nil { fatal(err) }
	if err := os.WriteFile(ss, shared, 0o644); err != nil { fatal(err) }

	fmt.Printf("wrote %s, %s\n", ct, ss)
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

func fatal(err error) { fmt.Fprintln(os.Stderr, "encaps:", err); os.Exit(1) }
