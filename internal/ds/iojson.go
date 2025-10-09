// internal/ds/iojson.go
package ds

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// ---- 공통 유틸 ----

func readJSONFile(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.UseNumber()
	return dec.Decode(v)
}

func toBigInt(x any) (*big.Int, error) {
	switch t := x.(type) {
	case json.Number:
		b := new(big.Int)
		if _, ok := b.SetString(t.String(), 10); !ok {
			return nil, fmt.Errorf("invalid number: %v", t)
		}
		return b, nil
	case string:
		// 문자열로 저장된 큰 정수도 허용
		b := new(big.Int)
		if _, ok := b.SetString(t, 10); !ok {
			return nil, fmt.Errorf("invalid string number: %v", t)
		}
		return b, nil
	case float64:
		// float로 들어온 경우(비권장) 정수로 캐스팅 시도
		b := new(big.Int)
		b.SetInt64(int64(t))
		return b, nil
	default:
		return nil, fmt.Errorf("unsupported number type: %T", x)
	}
}

func toBigIntSlice(x any) ([]*big.Int, error) {
	arr, ok := x.([]any)
	if !ok {
		return nil, fmt.Errorf("expected array, got %T", x)
	}
	out := make([]*big.Int, 0, len(arr))
	for _, e := range arr {
		b, err := toBigInt(e)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func toInt(x any) (int, error) {
	switch t := x.(type) {
	case json.Number:
		i, err := t.Int64()
		return int(i), err
	case float64:
		return int(t), nil
	case string:
		// 숫자 문자열 허용
		var num json.Number = json.Number(t)
		i, err := num.Int64()
		return int(i), err
	default:
		return 0, fmt.Errorf("unsupported int type: %T", x)
	}
}

// ---- Params ----
//
// 기대 JSON (예시):
// {
//   "P": 18446744073709551557,
//   "L": 64,
//   "K": 96,
//   "R": 79228162514264337593543950336
// }
//
// ds.Params 구조가 아래 필드명을 가진다고 가정합니다.
//   P *big.Int, R *big.Int, L int, K int
// 다르면 필드명만 맞춰주세요.

type paramsWire map[string]any

func LoadParams(path string) (*Params, error) {
	if path == "" {
		return DefaultParams(), nil
	}

	var raw paramsWire
	if err := readJSONFile(path, &raw); err != nil {
		return nil, err
	}

	if ok, pp, err := tryLoadGobParams(raw); ok {
		if err != nil {
			return nil, err
		}
		return normalizeParams(pp)
	}

	p := DefaultParams()

	if v, ok := raw["P"]; ok {
		b, err := toBigInt(v)
		if err != nil {
			return nil, err
		}
		p.P = b
	}

	if v, ok := raw["L"]; ok {
		i, err := toInt(v)
		if err != nil {
			return nil, err
		}
		if i > p.L {
			p.L = i
		}
	}

	if v, ok := raw["K"]; ok {
		i, err := toInt(v)
		if err != nil {
			return nil, err
		}
		p.K = i
	}

	return normalizeParams(p)
}

// ---- PublicKey ----
//
// 기대 JSON (예시, 사용자가 보여준 pk.json):
// {
//   "S1p": <num>, "S2p": <num>,
//   "Pprime": [..4..], "Qprime": [..4..],
//   "MuP": [..4..], "MuQ": [..4..],
//   "N": 3, "M": 1, "Lambda": 1
// }
//
// ds.PublicKey 구조가 아래 필드명을 가진다고 가정합니다.
//   S1p *big.Int; S2p *big.Int
//   Pprime []*big.Int; Qprime []*big.Int
//   MuP []*big.Int; MuQ []*big.Int
//   N int; M int; Lambda int
//
// 필드명이 다르면 아래 대입 부분에서 이름만 맞춰주세요.

type pkWire map[string]any

func LoadPublicKey(path string) (*PublicKey, error) {
	var raw pkWire
	if err := readJSONFile(path, &raw); err != nil {
		return nil, err
	}

	if ok, pk, err := tryLoadGobPublicKey(raw); ok {
		if err != nil {
			return nil, err
		}
		return pk, nil
	}

	var pk PublicKey

	// big scalars
	if v, ok := raw["S1p"]; ok {
		b, err := toBigInt(v)
		if err != nil {
			return nil, err
		}
		pk.S1p = b
	}
	if v, ok := raw["S2p"]; ok {
		b, err := toBigInt(v)
		if err != nil {
			return nil, err
		}
		pk.S2p = b
	}

	// big arrays
	if v, ok := raw["Pprime"]; ok {
		arr, err := toBigIntSlice(v)
		if err != nil {
			return nil, err
		}
		pk.Pprime = arr
	}
	if v, ok := raw["Qprime"]; ok {
		arr, err := toBigIntSlice(v)
		if err != nil {
			return nil, err
		}
		pk.Qprime = arr
	}
	if v, ok := raw["MuP"]; ok {
		arr, err := toBigIntSlice(v)
		if err != nil {
			return nil, err
		}
		pk.MuP = arr
	}
	if v, ok := raw["MuQ"]; ok {
		arr, err := toBigIntSlice(v)
		if err != nil {
			return nil, err
		}
		pk.MuQ = arr
	}

	// ints
	if v, ok := raw["N"]; ok {
		i, err := toInt(v)
		if err != nil {
			return nil, err
		}
		pk.N = i
	}
	if v, ok := raw["M"]; ok {
		i, err := toInt(v)
		if err != nil {
			return nil, err
		}
		pk.M = i
	}
	if v, ok := raw["Lambda"]; ok {
		i, err := toInt(v)
		if err != nil {
			return nil, err
		}
		pk.Lambda = i
	}

	return &pk, nil
}

// ---- Signature ----
//
// 현재 구현은 서명을 {"F": <num>, "H": <num>} 또는 각 항이 1개뿐인 배열로 저장한
// JSON을 지원한다. 배열이 비어있거나 두 개 이상인 경우는 오류로 처리한다.

type sigWire map[string]any

func LoadSignature(path string) (*Signature, error) {
	var raw sigWire
	if err := readJSONFile(path, &raw); err != nil {
		return nil, err
	}

	sig := &Signature{}

	fVal, ok := raw["F"]
	if !ok {
		return nil, errors.New("signature: missing F field")
	}
	fBig, err := firstBigInt(fVal)
	if err != nil {
		return nil, fmt.Errorf("signature: invalid F: %w", err)
	}
	sig.F = fBig

	hVal, ok := raw["H"]
	if !ok {
		return nil, errors.New("signature: missing H field")
	}
	hBig, err := firstBigInt(hVal)
	if err != nil {
		return nil, fmt.Errorf("signature: invalid H: %w", err)
	}
	sig.H = hBig

	return sig, nil
}

func firstBigInt(v any) (*big.Int, error) {
	switch t := v.(type) {
	case []any:
		if len(t) == 0 {
			return nil, errors.New("empty array")
		}
		if len(t) > 1 {
			return nil, fmt.Errorf("array length %d unsupported", len(t))
		}
		return toBigInt(t[0])
	default:
		return toBigInt(t)
	}
}

func loadGobBlob(raw map[string]any, target any) (bool, error) {
	formatVal, ok := raw["format"]
	if !ok {
		return false, nil
	}
	format, ok := formatVal.(string)
	if !ok || format != "gob-base64" {
		return false, nil
	}

	blobVal, ok := raw["blob"]
	if !ok {
		return false, errors.New("gob-base64: missing blob field")
	}
	blobStr, ok := blobVal.(string)
	if !ok {
		return false, errors.New("gob-base64: blob must be string")
	}

	rawBytes, err := base64.StdEncoding.DecodeString(blobStr)
	if err != nil {
		return true, err
	}
	if err := gob.NewDecoder(bytes.NewReader(rawBytes)).Decode(target); err != nil {
		return true, err
	}
	return true, nil
}

func tryLoadGobParams(raw paramsWire) (bool, *Params, error) {
	var pp Params
	matched, err := loadGobBlob(raw, &pp)
	if !matched {
		return false, nil, nil
	}
	if err != nil {
		return true, nil, err
	}
	return true, &pp, nil
}

func tryLoadGobPublicKey(raw pkWire) (bool, *PublicKey, error) {
	var pk PublicKey
	matched, err := loadGobBlob(raw, &pk)
	if !matched {
		return false, nil, nil
	}
	if err != nil {
		return true, nil, err
	}
	return true, &pk, nil
}

func normalizeParams(pp *Params) (*Params, error) {
	if pp == nil || pp.P == nil {
		return nil, errors.New("params: missing prime P")
	}

	norm := &Params{P: new(big.Int).Set(pp.P)}
	l := norm.P.BitLen()
	if pp.L > l {
		l = pp.L
	}
	norm.L = l

	k := pp.K
	minK := norm.P.BitLen() + 32
	if k < minK {
		k = minK
	}
	norm.K = k
	norm.R = new(big.Int).Lsh(big.NewInt(1), uint(norm.K))

	return norm, nil
}
