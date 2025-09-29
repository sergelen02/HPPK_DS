package fhe

import "testing"

func TestHomomorphicAddMul_NoOp(t *testing.T) {
    adp := NewNoopAdapter()
    sk, pk, err := adp.KeyGen()
    if err != nil || sk == nil || pk == nil {
        t.Fatalf("keygen err=%v", err)
    }

    m1, m2 := 12345, 6789
    c1, _ := adp.Enc(pk, m1)
    c2, _ := adp.Enc(pk, m2)

    addCT, _ := adp.Add(c1, c2)
    addPT, _ := adp.Dec(sk, addCT)
    if addPT != m1+m2 {
        t.Fatalf("add mismatch: got=%d want=%d", addPT, m1+m2)
    }

    mulCT, _ := adp.Mul(c1, c2)
    mulPT, _ := adp.Dec(sk, mulCT)
    if mulPT != m1*m2 {
        t.Fatalf("mul mismatch: got=%d want=%d", mulPT, m1*m2)
    }
}
