// cmd/verify/main.go (핵심 부분만)
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

func main() {
	pkPath     := flag.String("pk",     "artifacts/pk.json",     "public key JSON path")
	sigPath    := flag.String("sig",    "artifacts/sig.json",    "signature JSON path")
	msgPath    := flag.String("in",     "",                      "message file to verify")
	paramsPath := flag.String("params", "artifacts/params.json", "params JSON path (optional)")
	flag.Parse()

	if *msgPath == "" {
		log.Fatal("verify: -in <message file> is required")
	}

	// 1) 파라미터 로드(없으면 DefaultParams)
	pp, err := ds.LoadParams(*paramsPath) // 프로젝트에 로더가 없다면 만들어야 함 (UseNumber+big.Int 권장)
	if err != nil {
		pp = ds.DefaultParams()
	}

	// 2) 공개키/서명/메시지 로드
	pk,  err := ds.LoadPublicKey(*pkPath)   // 없으면 JSON 로더 구현 필요
	if err != nil { log.Fatal(err) }

	sig, err := ds.LoadSignature(*sigPath)  // 없으면 JSON 로더 구현 필요
	if err != nil { log.Fatal(err) }

	msg, err := os.ReadFile(*msgPath)
	if err != nil { log.Fatal(err) }

	// 3) 검증
	ok := ds.Verify(pp, pk, sig, msg)
	fmt.Println("verify:", ok)
	if !ok { os.Exit(1) } // 실패면 비-0 종료
}
