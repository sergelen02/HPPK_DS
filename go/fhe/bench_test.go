package fhe

import "testing"

func BenchmarkNoOp_Add(b *testing.B) {
    adp := NewNoopAdapter()
    _, pk, _ := adp.KeyGen()
    a, _ := adp.Enc(pk, 42)
    for i := 0; i < b.N; i++ {
        _, _ = adp.Add(a, a)
    }
}
func BenchmarkNoOp_Mul(b *testing.B) {
    adp := NewNoopAdapter()
    _, pk, _ := adp.KeyGen()
    a, _ := adp.Enc(pk, 42)
    for i := 0; i < b.N; i++ {
        _, _ = adp.Mul(a, a)
    }
}
