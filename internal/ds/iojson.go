// internal/ds/iojson.go
package ds

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
)

// ---- 공통 유틸 ----

func readJSONFile(path string, v any) error {
	f, err := os.Open(path)
	if err != nil { return err }
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
		if err != nil { return nil, err }
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
	var raw paramsWire
	if err := readJSONFile(path, &raw); err != nil {
		return nil, err
	}

	p := DefaultParams() // 기본값으로 시작
	// 개별 필드가 있으면 덮어씀
	if v, ok := raw["P"]; ok {
		b, err := toBigInt(v); if err != nil { return nil, err }
		p.P = b
	}
	if v, ok := raw["R"]; ok {
		b, err := toBigInt(v); if err != nil { return nil, err }
		p.R = b
	}
	if v, ok := raw["L"]; ok {
		i, err := toInt(v); if err != nil { return nil, err }
		p.L = i
	}
	if v, ok := raw["K"]; ok {
		i, err := toInt(v); if err != nil { return nil, err }
		// WithK가 있다면 메서드 사용, 아니면 직접 대입
		// p = p.WithK(i)
		p.K = i
	}
	return p, nil
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
	var pk PublicKey

	// big scalars
	if v, ok := raw["S1p"]; ok {
		b, err := toBigInt(v); if err != nil { return nil, err }
		pk.S1p = b
	}
	if v, ok := raw["S2p"]; ok {
		b, err := toBigInt(v); if err != nil { return nil, err }
		pk.S2p = b
	}

	// big arrays
	if v, ok := raw["Pprime"]; ok {
		arr, err := toBigIntSlice(v); if err != nil { return nil, err }
		pk.Pprime = arr
	}
	if v, ok := raw["Qprime"]; ok {
		arr, err := toBigIntSlice(v); if err != nil { return nil, err }
		pk.Qprime = arr
	}
	if v, ok := raw["MuP"]; ok {
		arr, err := toBigIntSlice(v); if err != nil { return nil, err }
		pk.MuP = arr
	}
	if v, ok := raw["MuQ"]; ok {
		arr, err := toBigIntSlice(v); if err != nil { return nil, err }
		pk.MuQ = arr
	}

	// ints
	if v, ok := raw["N"]; ok {
		i, err := toInt(v); if err != nil { return nil, err }
		pk.N = i
	}
	if v, ok := raw["M"]; ok {
		i, err := toInt(v); if err != nil { return nil, err }
		pk.M = i
	}
	if v, ok := raw["Lambda"]; ok {
		i, err := toInt(v); if err != nil { return nil, err }
		pk.Lambda = i
	}

	return &pk, nil
}

// ---- Signature ----
//
// 서명의 JSON 스키마는 레포마다 다릅니다.
// 아래는 흔한 예시 2가지 중 자동 감지:
//  A) { "F": [..2..], "H":[..2..], "Lambda": 1 }
//  B) { "F": <num>, "H": <num>, "Lambda": 1 }
//
// ds.Signature 구조가 다음 필드를 가진다고 가정합니다:
//   F []*big.Int 또는 *big.Int
//   H []*big.Int 또는 *big.Int
//   Lambda int
// 프로젝트 실제 구조와 다르면 필드명/형 맞춰서 수정하세요.

type sigWire map[string]any

func LoadSignature(path string) (*Signature, error) {
	// 먼저 원시 map으로 읽고, 필드 존재를 보고 분기
	var raw sigWire
	if err := readJSONFile(path, &raw); err != nil {
		return nil, err
	}

	var sig Signature

	// Lambda
	if v, ok := raw["Lambda"]; ok {
		i, err := toInt(v); if err != nil { return nil, err }
		setField(&sig, "Lambda", i)
	}

	// F
	if v, ok := raw["F"]; ok {
		switch reflect.TypeOf(v).Kind() {
		case reflect.Slice:
			arr, err := toBigIntSlice(v); if err != nil { return nil, err }
			if err := setField(&sig, "F", arr); err != nil { return nil, err }
		default:
			b, err := toBigInt(v); if err != nil { return nil, err }
			if err := setField(&sig, "F", b); err != nil { return nil, err }
		}
	}

	// H
	if v, ok := raw["H"]; ok {
		switch reflect.TypeOf(v).Kind() {
		case reflect.Slice:
			arr, err := toBigIntSlice(v); if err != nil { return nil, err }
			if err := setField(&sig, "H", arr); err != nil { return nil, err }
		default:
			b, err := toBigInt(v); if err != nil { return nil, err }
			if err := setField(&sig, "H", b); err != nil { return nil, err }
		}
	}

	return &sig, nil
}

// setField는 ds.Signature의 필드가 포인터/슬라이스/스칼라 어떤 형태든
// 이름으로 세팅을 시도합니다. (필드명이 다르면 아래를 맞추세요)
func setField(target any, name string, value any) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return errors.New("setField: target must be non-nil pointer")
	}
	v = v.Elem()
	f := v.FieldByName(name)
	if !f.IsValid() {
		// 필드가 없으면 무시 대신 에러로 알림
		return fmt.Errorf("setField: field %q not found on %T", name, target)
	}
	if !f.CanSet() {
		return fmt.Errorf("setField: field %q not settable", name)
	}
	val := reflect.ValueOf(value)
	// 슬라이스<-슬라이스, 포인터<-포인터, 스칼라<-스칼라만 허용
	if !val.Type().AssignableTo(f.Type()) {
		return fmt.Errorf("setField: cannot assign %v to %v", val.Type(), f.Type())
	}
	f.Set(val)
	return nil
}
