package fhe

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func BenchmarkDepth(b *testing.B) {
	adp := getAdapter(&testing.T{})
	pk, sk, _ := adp.KeyGen()
	modulus := new(big.Int).Lsh(big.NewInt(1), 61)

	m := func() *big.Int { x, _ := rand.Int(rand.Reader, modulus); return x }

	b.Run("add-depth-32", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ct, _ := adp.Enc(pk, m())
			for k := 0; k < 32; k++ {
				ct, _ = adp.Add(ct, ct)
			} // 같은 값 반복 더하기
			_, _ = adp.Dec(sk, ct)
		}
	})

	b.Run("mul-depth-8", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ct, _ := adp.Enc(pk, m())
			for k := 0; k < 8; k++ {
				ct, _ = adp.Mul(ct, ct)
			} // 제곱 반복
			_, _ = adp.Dec(sk, ct)
		}
	})
}
