package kem

import "testing"

func TestEncapsDecaps(t *testing.T) {
	adp := NewNoopAdapter()
	sk, pk, err := adp.KeyGen()
	if err != nil { t.Fatalf("KeyGen: %v", err) }

	ct, ss1, err := adp.Encaps(pk)
	if err != nil { t.Fatalf("Encaps: %v", err) }

	ss2, err := adp.Decaps(sk, ct)
	if err != nil { t.Fatalf("Decaps: %v", err) }

	if string(ss1) != string(ss2) {
		t.Fatalf("shared secret mismatch")
	}
}
