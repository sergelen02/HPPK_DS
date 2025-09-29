package kem

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

type SecretKey struct{ raw []byte }
type PublicKey struct{ raw []byte }
type Ciphertext struct{ raw []byte }

type Adapter interface {
	KeyGen() (*SecretKey, *PublicKey, error)
	Encaps(pk *PublicKey) (*Ciphertext, []byte, error)
	Decaps(sk *SecretKey, ct *Ciphertext) ([]byte, error)
}

type NoopAdapter struct{}

func NewNoopAdapter() *NoopAdapter { return &NoopAdapter{} }

func (a *NoopAdapter) KeyGen() (*SecretKey, *PublicKey, error) {
	sk := make([]byte, 32)
	pk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sk); err != nil { return nil, nil, err }
	if _, err := io.ReadFull(rand.Reader, pk); err != nil { return nil, nil, err }
	return &SecretKey{raw: sk}, &PublicKey{raw: pk}, nil
}

func (a *NoopAdapter) Encaps(pk *PublicKey) (*Ciphertext, []byte, error) {
	if pk == nil || len(pk.raw) == 0 { return nil, nil, errors.New("nil pk") }
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil { return nil, nil, err }
	ss := sha256.Sum256(seed)
	return &Ciphertext{raw: seed}, ss[:], nil
}

func (a *NoopAdapter) Decaps(sk *SecretKey, ct *Ciphertext) ([]byte, error) {
	if ct == nil || len(ct.raw) == 0 { return nil, errors.New("nil ct") }
	ss := sha256.Sum256(ct.raw)
	return ss[:], nil
}