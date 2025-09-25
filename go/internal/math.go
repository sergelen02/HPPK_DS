package ds

import "math/big"

func mod(a, m *big.Int) *big.Int {
	x := new(big.Int).Mod(a, m)
	if x.Sign() < 0 { x.Add(x, m) }
	return x
}
func addMod(a,b,m *big.Int)*big.Int{ t:=new(big.Int).Add(a,b); return mod(t,m) }
func subMod(a,b,m *big.Int)*big.Int{ t:=new(big.Int).Sub(a,b); return mod(t,m) }
func mulMod(a,b,m *big.Int)*big.Int{ t:=new(big.Int).Mul(a,b); return mod(t,m) }
func invMod(a,m *big.Int)*big.Int{ return new(big.Int).ModInverse(a,m) }

func expMod(x *big.Int, e int, m *big.Int)*big.Int{
	res := big.NewInt(1); base := new(big.Int).Set(x)
	for i:=0;i<e;i++{ res = mulMod(res, base, m) }
	return res
}

func barrettFloor(H, mu, R *big.Int, K int) *big.Int {
	t := new(big.Int).Mul(H, mu)
	t.Rsh(t, uint(K))
	return t
}
