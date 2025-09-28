package fhe

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// getAdapter: 실제 어댑터를 주입하세요.
// 환경변수/빌드태그로 구현체를 스위치할 수 있습니다.
func getAdapter(t *testing.T) Adapter {
	t.Helper()
	// TODO: 사용자의 실제 어댑터 반환
	t.Fatalf("Adapter not wired: implement getAdapter() to return your FHE adapter")
	return nil
}

func randBig(max *big.Int) *big.Int {
	x, _ := rand.Int(rand.Reader, max)
	return x
}

func TestHomomorphicAddMul(t *testing.T) {
	adp := getAdapter(t)

	pk, sk, err := adp.KeyGen()
	if err != nil {
		t.Fatalf("KeyGen error: %v", err)
	}

	// 실험 파라미터
	modulus := new(big.Int).Lsh(big.NewInt(1), 61) // 예: 61-bit 모듈러 (필요 시 교체)

	cases := []struct {
		name   string
		trials int
	}{
		{"small", 64}, {"medium", 256}, {"large", 1024},
	}

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			for i := 0; i < cs.trials; i++ {
				m1 := randBig(modulus)
				m2 := randBig(modulus)

				ct1, err := adp.Enc(pk, m1)
				if err != nil {
					t.Fatalf("enc1: %v", err)
				}
				ct2, err := adp.Enc(pk, m2)
				if err != nil {
					t.Fatalf("enc2: %v", err)
				}

				// Add test: Dec(Enc(m1)+Enc(m2)) == (m1+m2) mod modulus
				addCT, err := adp.Add(ct1, ct2)
				if err != nil {
					t.Fatalf("add: %v", err)
				}
				addPT, err := adp.Dec(sk, addCT)
				if err != nil {
					t.Fatalf("dec add: %v", err)
				}
				wantAdd := new(big.Int).Mod(new(big.Int).Add(m1, m2), modulus)
				if addPT.Cmp(wantAdd) != 0 {
					t.Fatalf("homomorphic add mismatch: got %v want %v", addPT, wantAdd)
				}

				// Mul test: Dec(Enc(m1)*Enc(m2)) == (m1*m2) mod modulus
				mulCT, err := adp.Mul(ct1, ct2)
				if err != nil {
					t.Fatalf("mul: %v", err)
				}
				mulPT, err := adp.Dec(sk, mulCT)
				if err != nil {
					t.Fatalf("dec mul: %v", err)
				}
				wantMul := new(big.Int).Mod(new(big.Int).Mul(m1, m2), modulus)
				if mulPT.Cmp(wantMul) != 0 {
					t.Fatalf("homomorphic mul mismatch: got %v want %v", mulPT, wantMul)
				}
			}
		})
	}
}
