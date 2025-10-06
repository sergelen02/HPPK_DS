package ds

import (
	"errors"
	"math/big"
)

func KeyGen(pp *Params, n, m, lambda int) (*SecretKey, *PublicKey, error) {
	if pp == nil || pp.P == nil || pp.R == nil {
		return nil, nil, errors.New("nil params")
	}
	if lambda < 1 { lambda = 1 }
	if n < 1 { n = 1 }
	if m < 1 { m = 1 }
	N := n + lambda

	R1, S1, err := randCoprimePair(pp.L); if err != nil { return nil, nil, err }
	R2, S2, err := randCoprimePair(pp.L); if err != nil { return nil, nil, err }

	fc := make([]*big.Int, lambda+1)
	hc := make([]*big.Int, lambda+1)
	for i := 0; i <= lambda; i++ {
		if fc[i], err = randZp(pp.P); err != nil { return nil, nil, err }
		if hc[i], err = randZp(pp.P); err != nil { return nil, nil, err }
	}

	pcoef := make([]*big.Int, (N+1)*m)
	qcoef := make([]*big.Int, (N+1)*m)
	for j := 0; j < m; j++ {
		b := make([]*big.Int, n+1)
		for t := 0; t <= n; t++ { if b[t], err = randZp(pp.P); err != nil { return nil, nil, err } }
		for i := 0; i <= N; i++ {
			accP := new(big.Int); accQ := new(big.Int)
			for t := 0; t <= i; t++ {
				if t <= lambda && (i-t) <= n {
					accP = modAdd(accP, modMul(fc[t], b[i-t], pp.P), pp.P)
					accQ = modAdd(accQ, modMul(hc[t], b[i-t], pp.P), pp.P)
				}
			}
			pcoef[idxIJ(i, j, m)] = accP
			qcoef[idxIJ(i, j, m)] = accQ
		}
	}

	Pij := make([]*big.Int, (N+1)*m)
	Qij := make([]*big.Int, (N+1)*m)
	for i := 0; i <= N; i++ {
		for j := 0; j < m; j++ {
			k := idxIJ(i, j, m)
			Pij[k] = new(big.Int).Mul(R1, pcoef[k]); Pij[k].Mod(Pij[k], S1)
			Qij[k] = new(big.Int).Mul(R2, qcoef[k]); Qij[k].Mod(Qij[k], S2)
		}
	}

	R := pp.R
	MuP := make([]*big.Int, (N+1)*m)
	MuQ := make([]*big.Int, (N+1)*m)
	Pprime := make([]*big.Int, (N+1)*m)
	Qprime := make([]*big.Int, (N+1)*m)

	beta, err := randZp(pp.P); if err != nil { return nil, nil, err }
	S1p := new(big.Int).Mul(beta, S1); S1p.Mod(S1p, pp.P)
	S2p := new(big.Int).Mul(beta, S2); S2p.Mod(S2p, pp.P)

	for idx := 0; idx < (N+1)*m; idx++ {
		tmp := new(big.Int).Mul(R, Pij[idx]); MuP[idx] = new(big.Int).Div(tmp, S1)
		tmp2 := new(big.Int).Mul(R, Qij[idx]); MuQ[idx] = new(big.Int).Div(tmp2, S2)
		Pprime[idx] = new(big.Int).Mul(beta, Pij[idx]); Pprime[idx].Mod(Pprime[idx], pp.P)
		Qprime[idx] = new(big.Int).Mul(beta, Qij[idx]); Qprime[idx].Mod(Qprime[idx], pp.P)
	}

	sk := &SecretKey{
		R1: R1, S1: S1, R2: R2, S2: S2,
		FCoeffs: fc, HCoeffs: hc, Lambda: lambda,
	}
	pk := &PublicKey{
		S1p: S1p, S2p: S2p,
		Pprime: Pprime, Qprime: Qprime,
		MuP: MuP, MuQ: MuQ,
		N: N, M: m, Lambda: lambda,
	}
	return sk, pk, nil
}
