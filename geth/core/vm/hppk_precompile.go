package vm

import (
	"errors"
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

// go-ethereum/core/vm.PrecompiledContract 요구사항: Name 도 구현
func (pc *HPPKPrecompile) Name() string { return "HPPKVerify" }

// 입력 사이즈에 선형인 결정적 가스 모델(대략치). 필요시 실측치로 조정.
func (pc *HPPKPrecompile) RequiredGas(input []byte) uint64 {
	// base + per-byte + per-item 가중치 (RLP 오버헤드 포함 보수적 추정)
	const base = 5_000
	const perByte = 15
	return base + uint64(len(input))*perByte
}

func (pc *HPPKPrecompile) Run(input []byte) ([]byte, error) {
	if pc.PP == nil || pc.PP.P == nil {
		return []byte{0}, errors.New("params not initialized")
	}
	var in VerifyInput
	if err := rlp.DecodeBytes(input, &in); err != nil {
		return []byte{0}, err
	}

	// 길이 정합성 체크
	n := len(in.Pprime)
	if n == 0 || n != len(in.Qprime) || n != len(in.Mu) || n != len(in.Nu) {
		return []byte{0}, errors.New("length mismatch among Pprime/Qprime/Mu/Nu")
	}

	// 공개키 구성(미리할당 + 인덱스 대입)
	pk := &ds.PublicKey{
		S1p:    new(big.Int).SetBytes(in.S1p),
		S2p:    new(big.Int).SetBytes(in.S2p),
		Pprime: make([]*big.Int, n),
		Qprime: make([]*big.Int, n),
		Mu:     make([]*big.Int, n),
		Nu:     make([]*big.Int, n),
	}
	// 모듈러 정규화 helper
	mod := pc.PP.P
	modNorm := func(z *big.Int) *big.Int {
		if z == nil {
			return new(big.Int)
		}
		z.Mod(z, mod)
		if z.Sign() < 0 {
			z.Add(z, mod)
		}
		return z
	}

	for i := 0; i < n; i++ {
		pk.Pprime[i] = modNorm(new(big.Int).SetBytes(in.Pprime[i]))
		pk.Qprime[i] = modNorm(new(big.Int).SetBytes(in.Qprime[i]))
		pk.Mu[i] = modNorm(new(big.Int).SetBytes(in.Mu[i]))
		pk.Nu[i] = modNorm(new(big.Int).SetBytes(in.Nu[i]))
	}
	pk.S1p = modNorm(pk.S1p)
	pk.S2p = modNorm(pk.S2p)

	sig := &ds.Signature{
		F: modNorm(new(big.Int).SetBytes(in.SigF)),
		H: modNorm(new(big.Int).SetBytes(in.SigH)),
	}

	ok := ds.Verify(pc.PP, pk, in.Msg, sig)
	if ok {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}
