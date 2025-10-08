package iohelper

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"os"

	"github.com/sergelen02/HPPK_DS/internal/ds"
)

type SigBlob struct {
	Format string `json:"format"` // "gob-base64"
	Blob   string `json:"blob"`   // base64(gob(data))
}

func SaveGobBase64(path string, v any) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil { return err }
	sb := SigBlob{Format: "gob-base64", Blob: base64.StdEncoding.EncodeToString(buf.Bytes())}
	f, err := os.Create(path); if err != nil { return err }
	defer f.Close()
	enc := json.NewEncoder(f); enc.SetIndent("", "  ")
	return enc.Encode(&sb)
}

func LoadGobBase64(path string, v any) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil { return false, err }
	var sb SigBlob
	if err := json.Unmarshal(b, &sb); err != nil { return false, err }
	if sb.Format != "gob-base64" || sb.Blob == "" { return false, nil }
	raw, err := base64.StdEncoding.DecodeString(sb.Blob)
	if err != nil { return false, err }
	return true, gob.NewDecoder(bytes.NewReader(raw)).Decode(v)
}

// ---------- 키/파라미터 ----------

// 저장은 gob-base64로, 로딩은 gob-base64 먼저 시도 후 JSON 폴백
func SavePublicKey(path string, pk *ds.PublicKey) error {
	return SaveGobBase64(path, pk)
}
func LoadPublicKey(path string) (*ds.PublicKey, error) {
	var pk ds.PublicKey
	if ok, err := LoadGobBase64(path, &pk); err != nil { return nil, err } else if ok {
		return &pk, nil
	}
	// JSON fallback
	f, err := os.Open(path); if err != nil { return nil, err }
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&pk); err != nil { return nil, err }
	return &pk, nil
}

func SaveSecretKey(path string, sk *ds.SecretKey) error {
	return SaveGobBase64(path, sk)
}
func LoadSecretKey(path string) (*ds.SecretKey, error) {
	var sk ds.SecretKey
	if ok, err := LoadGobBase64(path, &sk); err != nil { return nil, err } else if ok {
		return &sk, nil
	}
	f, err := os.Open(path); if err != nil { return nil, err }
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&sk); err != nil { return nil, err }
	return &sk, nil
}

func SaveParams(path string, pp *ds.Params) error {
	return SaveGobBase64(path, pp)
}
func LoadParams(path string) (*ds.Params, error) {
	if path == "" { return ds.DefaultParams(), nil }
	var pp ds.Params
	if ok, err := LoadGobBase64(path, &pp); err != nil { return nil, err } else if ok {
		return &pp, nil
	}
	f, err := os.Open(path); if err != nil { return nil, err }
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&pp); err != nil { return nil, err }
	return &pp, nil
}

func Must[T any](v *T, err error) *T {
	if err != nil { panic(err) }
	return v
}
