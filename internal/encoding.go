package ds

import "math/big"

func bigsToBytes(arr []*big.Int) [][]byte {
	out := make([][]byte, len(arr))
	for i,x := range arr { out[i]=x.Bytes() }
	return out
}
