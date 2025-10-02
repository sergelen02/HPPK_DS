package vm

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/rlp"
	ds "github.com/sergelen02/HPPK_DS/internal/ds"
)

// RLP 입력 포맷(한 번에 검증까지 수행)
// N: x의 최고지수(실제 항은 0..N → N+1개), M: u 변숫개수
// 1차원 평탄화 규칙: idx = i*M + j  (i in [0..N], j in [0..M-1])
type VerifyInput struct {
	Msg    []byte
	SigF   []byte
	SigH   []byte

	// 각 항목 길이 == (N+1)*M  이어야 함
	Pprime [][]byte // p'_{ij} = β·P_{ij} mod p
	Qprime [][]byte // q'_{ij} = β·Q_{ij} mod p
	MuP    [][]byte // μ_{ij} = floor(R·P_{ij}/S1)
	MuQ    [][]byte // ν_{ij} = floor(R·Q_{ij}/S2)

	S1p []byte      // s1 = β·S1 mod p
	S2p []byte      // s2 = β·S2 mod p
	N   uint32      // 다항 차수(확장 후) 상한
	M   uint32      // u 변수 개수
}

type HPPKPrecompile struct{ PP *ds.Params } // PP에는 p, K, R(=1<<K) 포함

func (pc *HPPKPrecompile) Name() string { return "HPPKVerify" }

// 입력 길이에 선형인 보수적 가스 모델(실측 후 재보정 권장)
func (pc *HPPKPrecompile) RequiredGas(input []byte) uint64 {
	const base = 5_000
	const perByte = 15
	return base + uint64(len(input))*perByte
}

func (pc *HPPKPrecompile) Run(input []byte) ([]byte, error) {
	if pc.PP == nil || pc.PP.P == nil || pc.PP.R == nil {
		return []byte{0}, errors.New("params not initialized")
	}
	var in VerifyInput
	if err := rlp.DecodeBytes(input, &in); err != nil {
		return []byte{0}, err
	}

	// 차원/길이 검증
	if in.M == 0 {
		return []byte{0}, errors.New("M must be > 0")
	}
	if in.N == 0 && len(in.Pprime) == 0 {
		return []byte{0}, errors.New("invalid N and empty arrays")
	}
	expect := int((in.N + 1) * in.M)
	if expect != len(in.Pprime) ||
		expect != len(in.Qprime) ||
		expect != len(in.MuP) ||
		expect != len(in.MuQ) {
		return []byte{0}, errors.New("length mismatch: arrays must be (N+1)*M")
	}

	p := pc.PP.P
	modNorm := func(b []byte) *big.Int {
		z := new(big.Int).SetBytes(b)
		z.Mod(z, p)
		if z.Sign() < 0 {
			z.Add(z, p)
		}
		return z
	}

	// 공개키 구성
	pk := &ds.PublicKey{
		S1p:    modNorm(in.S1p),
		S2p:    modNorm(in.S2p),
		Pprime: make([]*big.Int, expect),
		Qprime: make([]*big.Int, expect),
		MuP:    make([]*big.Int, expect),
		MuQ:    make([]*big.Int, expect),
		N:      int(in.N),
		M:      int(in.M),
		// Lambda는 검증에서 직접 쓰지 않으므로 0으로 둬도 무방
	}

	for i := 0; i < expect; i++ {
		pk.Pprime[i] = modNorm(in.Pprime[i])
		pk.Qprime[i] = modNorm(in.Qprime[i])
		// 주의: μ/ν는 mod p가 아니라 정수(shift 전 피제수)이지만,
		// DS 구현에서 floor((F*μ)/R)를 바로 >>K로 쓰므로 p로 줄이지 않아도 동작함.
		// 다만 안전히 big.Int로 받아두고, Verify 내부에서 곱/쉬프트에만 사용.
		pk.MuP[i] = new(big.Int).SetBytes(in.MuP[i])
		pk.MuQ[i] = new(big.Int).SetBytes(in.MuQ[i])
	}

	// 서명
	sig := &ds.Signature{
		F: modNorm(in.SigF),
		H: modNorm(in.SigH),
	}

	// 검증 호출(순서: pp, pk, sig, msg)
	if ds.Verify(pc.PP, pk, sig, in.Msg) {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}
