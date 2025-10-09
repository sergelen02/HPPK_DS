package iohelper
// cmd/common/iohelper/iohelper.go

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"os"

	ds "github.com/sergelen02/HPPK_DS/internal/ds"
)

type blob struct {
	Format string `json:"format"` // "gob-base64"
	Blob   string `json:"blob"`
}

func saveGobBase64(path string, v any) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil { return err }
	sb := blob{Format: "gob-base64", Blob: base64.StdEncoding.EncodeToString(buf.Bytes())}
	f, err := os.Create(path); if err != nil { return err }
	defer f.Close()
	enc := json.NewEncoder(f); enc.SetIndent("", "  ")
	return enc.Encode(&sb)
}

func loadGobBase64(path string, v any) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil { return false, err }
	var sb blob
	if err := json.Unmarshal(b, &sb); err != nil { return false, err }
	if sb.Format != "gob-base64" || sb.Blob == "" { return false, nil }
	raw, err := base64.StdEncoding.DecodeString(sb.Blob)
	if err != nil { return false, err }
	return true, gob.NewDecoder(bytes.NewReader(raw)).Decode(v)
}

// ---------- Params ----------
func SaveParams(path string, pp *ds.Params) error { return saveGobBase64(path, pp) }
func LoadParams(path string) (*ds.Params, error) {
	if path == "" { return ds.DefaultParams(), nil }
	var pp ds.Params
	if ok, err := loadGobBase64(path, &pp); err != nil { return nil, err } else if ok {
		return &pp, nil
	}
	f, err := os.Open(path); if err != nil { return nil, err }
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&pp); err != nil { return nil, err }
	return &pp, nil
}

// ---------- Secret/Public Keys ----------
func SaveSecretKey(path string, sk *ds.SecretKey) error { return saveGobBase64(path, sk) }
func LoadSecretKey(path string) (*ds.SecretKey, error) {
	var sk ds.SecretKey
	if ok, err := loadGobBase64(path, &sk); err != nil { return nil, err } else if ok {
		return &sk, nil
	}
	f, err := os.Open(path); if err != nil { return nil, err }
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&sk); err != nil { return nil, err }
	return &sk, nil
}

func SavePublicKey(path string, pk *ds.PublicKey) error { return saveGobBase64(path, pk) }
func LoadPublicKey(path string) (*ds.PublicKey, error) {
	var pk ds.PublicKey
	if ok, err := loadGobBase64(path, &pk); err != nil { return nil, err } else if ok {
		return &pk, nil
	}
	f, err := os.Open(path); if err != nil { return nil, err }
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&pk); err != nil { return nil, err }
	return &pk, nil
}

// 작은 헬퍼
func Must[T any](v *T, err error) *T {
	if err != nil { panic(err) }
	return v
}
