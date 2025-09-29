package fhe

// 최소 타입 (더미용)
type SecKey struct{}
type PubKey struct{}
type Ciphertext struct{ v int }

// 실험 공용 인터페이스
type Adapter interface {
    KeyGen() (*SecKey, *PubKey, error)
    Enc(pk *PubKey, m int) (*Ciphertext, error)
    Dec(sk *SecKey, ct *Ciphertext) (int, error)
    Add(a, b *Ciphertext) (*Ciphertext, error)
    Mul(a, b *Ciphertext) (*Ciphertext, error)
}
