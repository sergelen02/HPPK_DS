package vm

import (
	"time"
	"github.com/ethereum/go-ethereum/metrics"
)

var (
	mVerifyCount = metrics.NewCounter("hppk/verify/count")
	mVerifyFail  = metrics.NewCounter("hppk/verify/fail")
	mVerifyDur   = metrics.NewTimer("hppk/verify/duration")
)

func (pc *HPPKPrecompile) RunWithMetrics(input []byte) ([]byte, error) {
	start := time.Now()
	out, err := pc.Run(input)
	mVerifyDur.Update(time.Since(start))
	mVerifyCount.Inc(1)
	if err != nil || (len(out)==1 && out[0]==0) { mVerifyFail.Inc(1) }
	return out, err
}
