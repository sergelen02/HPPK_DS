package fhe

import "errors"

type noopAdapter struct{}

func NewNoopAdapter() Adapter { return &noopAdapter{} }

func (n *noopAdapter) KeyGen() (*SecretKey, *PublicKey, error) {
	return &SecKey{}, &PubKey{}, nil
}

func (n *noopAdapter) Enc(pk *PubKey, m int) (*Ciphertext, error) {
	if pk == nil {
		return nil, errors.New("nil pubkey")
	}
	return &Ciphertext{v: m}, nil
}

func (n *noopAdapter) Dec(sk *SecretKey, ct *Ciphertext) (int, error) {
	if sk == nil || ct == nil {
		return 0, errors.New("nil arg")
	}
	return ct.v, nil
}

func (n *noopAdapter) Add(a, b *Ciphertext) (*Ciphertext, error) {
	if a == nil || b == nil {
		return nil, errors.New("nil add operand")
	}
	return &Ciphertext{v: a.v + b.v}, nil
}

func (n *noopAdapter) Mul(a, b *Ciphertext) (*Ciphertext, error) {
	if a == nil || b == nil {
		return nil, errors.New("nil mul operand")
	}
	return &Ciphertext{v: a.v * b.v}, nil
}
