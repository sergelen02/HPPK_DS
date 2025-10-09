package main

import (
	"bytes"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// 간단한 유사도 척도(가중치 합 100점)
// 1) KeyGen/Sign/Verify 함수 시그니처 존재(각 8점)
// 2) β fold: p′=β·P, q′=β·Q, s1=β·S1, s2=β·S2 (각 6점, 총 24)
// 3) Barrett 전처리: μ_i=floor(R*Pij/S1), ν_i=floor(R*Qij/S2) (각 10점, 총 20)
// 4) Verify에서 U_i(H)=H*p′_i - s1*floor(H*μ_i/R), V_i(F)=F*q′_i - s2*floor(F*ν_i/R) (각 10점, 총 20)
// 5) f,h 일차 다항과 해시-청크 처리(각 6점, 총 12)
// 6) 파라미터: p(소수), L, K(R=2^K) 선언(8점)
type item struct{ name string; pts int; found bool }

func main() {
	root := "."
	var files []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil { return nil }
		if d.IsDir() { 
			// vendor/, .git/ 등 스킵
			if strings.Contains(p, "/vendor") || strings.Contains(p, "/.git") { return filepath.SkipDir }
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			files = append(files, p)
		}
		return nil
	})

	readAll := func() string {
		var b bytes.Buffer
		for _, f := range files {
			data, _ := os.ReadFile(f)
			b.Write(data)
			b.WriteString("\n")
		}
		return b.String()
	}
	src := readAll()

	checks := []item{
		{"func KeyGen(", 8, strings.Contains(src, "func KeyGen(")},
		{"func Sign(", 8, strings.Contains(src, "func Sign(")},
		{"func Verify(", 8, strings.Contains(src, "func Verify(")},
		{"beta*P (p′)", 6, regexp.MustCompile(`beta.*\*.*P|P.*\*.*beta`).MatchString(src)},
		{"beta*Q (q′)", 6, regexp.MustCompile(`beta.*\*.*Q|Q.*\*.*beta`).MatchString(src)},
		{"s1=beta*S1", 6, regexp.MustCompile(`S1.*=.*beta.*\*.*S1|s1.*:=.*beta.*\*.*S1|S1beta`).MatchString(src)},
		{"s2=beta*S2", 6, regexp.MustCompile(`S2.*=.*beta.*\*.*S2|s2.*:=.*beta.*\*.*S2|S2beta`).MatchString(src)},
		{"mu=floor(R*P/S1)", 10, regexp.MustCompile(`Div\(\s*Mul\(\s*R\s*,\s*P`).MatchString(src) || strings.Contains(src, "floor(R*P") },
		{"nu=floor(R*Q/S2)", 10, regexp.MustCompile(`Div\(\s*Mul\(\s*R\s*,\s*Q`).MatchString(src) || strings.Contains(src, "floor(R*Q") },
		{"Verify U_i(H)=H*p′-s1*floor(H*mu/R)", 10, regexp.MustCompile(`floor\(.*H.*mu.*\/.*R\)|Div\(\s*Mul\(\s*H\s*,\s*mu`).MatchString(src)},
		{"Verify V_i(F)=F*q′-s2*floor(F*nu/R)", 10, regexp.MustCompile(`floor\(.*F.*nu.*\/.*R\)|Div\(\s*Mul\(\s*F\s*,\s*nu`).MatchString(src)},
		{"f(x)=f0+f1*x, h(x)=...", 6, regexp.MustCompile(`f0.*\+.*f1.*\*.*x|F0.*Add.*F1`).MatchString(src) && regexp.MustCompile(`h0.*\+.*h1.*\*.*x|H0.*Add.*H1`).MatchString(src)},
		{"hash->chunks (SHA-256 or SHAKE)", 6, regexp.MustCompile(`sha256|SHAKE`).MatchString(src) && strings.Contains(src, "chunks")},
		{"params: p, L, K, R=2^K", 8, regexp.MustCompile(`var .*p|P\s*=\s*big.NewInt|Lbits|Kbits|R\s*=\s*new\(big.Int\).*Lsh`).MatchString(src)},
	}

	total := 0
	got := 0
	for i := range checks {
		total += checks[i].pts
		if checks[i].found { got += checks[i].pts }
	}
	// 빌드 에러 수 카운트(간단)
	errCount := 0
	for _, f := range files {
		fset := token.NewFileSet()
		if _, err := parser.ParseFile(fset, f, nil, 0); err != nil {
			errCount++
		}
	}
	fmt.Printf("ALGO_SIMILARITY=%d/%d (%.1f%%)\n", got, total, 100*float64(got)/float64(total))
	fmt.Printf("BUILD_PARSE_ERRORS=%d (파일 파싱 에러 수)\n", errCount)
	for _, c := range checks {
		fmt.Printf("[%-40s] %v (+%d)\n", c.name, c.found, c.pts)
	}
}
