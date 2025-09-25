package vm

import (
	"math/big"
	"github.com/ethereum/go-ethereum/rlp"
	ds "github.com/sergelen02/HPPK_DS/internal/ds"
)

type VerifyInput struct {
	Msg    []byte
	SigF   []byte
	SigH   []byte
	Pprime [][]byte
	Qprime [][]byte
	Mu     [][]byte
	Nu     [][]byte
	S1p    []byte
	S2p    []byte
}

type HPPKPrecompile struct{ PP *ds.Params }

func (pc *HPPKPrecompile) RequiredGas(input []byte) uint64 {
	return 5000 + uint64(len(input))*15 // 실측 후 보정
}

func (pc *HPPKPrecompile) Run(input []byte) ([]byte, error) {
	var in VerifyInput
	if err := rlp.DecodeBytes(input, &in); err != nil { return []byte{0}, err }

	pk := &ds.PublicKey{
		S1p: new(big.Int).SetBytes(in.S1p),
		S2p: new(big.Int).SetBytes(in.S2p),
	}
	for _,b := range in.Pprime { pk.Pprime = append(pk.Pprime, new(big.Int).SetBytes(b)) }
	for _,b := range in.Qprime { pk.Qprime = append(pk.Qprime, new(big.Int).SetBytes(b)) }
	for _,b := range in.Mu     { pk.Mu     = append(pk.Mu,     new(big.Int).SetBytes(b)) }
	for _,b := range in.Nu     { pk.Nu     = append(pk.Nu,     new(big.Int).SetBytes(b)) }

	sig := &ds.Signature{
		F: new(big.Int).SetBytes(in.SigF),
		H: new(big.Int).SetBytes(in.SigH),
	}
	ok := ds.Verify(pc.PP, pk, in.Msg, sig)
	if ok { return []byte{1}, nil }
	return []byte{0}, nil
}
