package kem
// internal/kem/kem.go

type PublicKey struct{}
type SecretKey struct{}

func LoadPublicKey(path string) (*PublicKey, error) { return &PublicKey{}, nil }
func LoadSecretKey(path string) (*SecretKey, error) { return &SecretKey{}, nil }
func Encaps(pk *PublicKey) ([]byte, []byte, error)  { return []byte("ct"), []byte("ss"), nil }
func Decaps(sk *SecretKey, ct []byte) ([]byte, error) { return []byte("ss"), nil }
