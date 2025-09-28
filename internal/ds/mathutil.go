package ds

import "math/big"

// (a + b) mod m
func addMod(a, b, m *big.Int) *big.Int {
	var t big.Int
	t.Add(a, b)
	t.Mod(&t, m)
	// Mod 결과는 0..m-1 범위라 음수 보정은 불필요하지만, 안전을 위해 유지해도 무방
	if t.Sign() < 0 {
		t.Add(&t, m)
	}
	return new(big.Int).Set(&t)
}

// (a - b) mod m
func subMod(a, b, m *big.Int) *big.Int {
	var t big.Int
	t.Sub(a, b)
	t.Mod(&t, m)
	if t.Sign() < 0 {
		t.Add(&t, m)
	}
	return new(big.Int).Set(&t)
}

// (a * b) mod m
func mulMod(a, b, m *big.Int) *big.Int {
	var t big.Int
	t.Mul(a, b)
	t.Mod(&t, m)
	return new(big.Int).Set(&t)
}

// a^e mod m  (e: int >= 0)
// a^e mod m  (e: int >= 0)
func powModInt(a *big.Int, e int, m *big.Int) *big.Int {
	if e < 0 {
		// 필요 시 역원 처리로 확장 가능
		return big.NewInt(0)
	}
	var ee big.Int
	ee.SetInt64(int64(e))
	var out big.Int
	out.Exp(a, &ee, m)
	return new(big.Int).Set(&out)
}

// Barrett-like floor: floor( x * mu / R )  where R = 2^K
// 주의: 여기서는 R(=2^K) 자체를 인자로 받아 정확히 사용합니다.
func barrettFloor(x, mu, R *big.Int, K int) *big.Int {
	var t big.Int
	t.Mul(x, mu)
	// R = 2^K 라면 Div(&t, R) 와 동일하지만, 기존 코드 유지 의도면 그대로 둠
	t.Div(&t, R)
	return new(big.Int).Set(&t)
}

// 역원 유틸 (필요 시 사용)
func ModInverseOrErr(a, m *big.Int) (*big.Int, error) {
	inv := new(big.Int).ModInverse(a, m)
	if inv == nil {
		return nil, ErrNoInverse
	}
	return inv, nil
}

// invMod: 역원이 없으면 nil 반환
func invMod(a, m *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, m)
}

func hashToX(P *big.Int, msg []byte) *big.Int {
    h := sha256.Sum256(msg)
    x := new(big.Int).SetBytes(h[:])
    x.Mod(x, P)
    if x.Sign() == 0 {
        x.SetInt64(1)
    }

	  return x
}