package vm

import (
	"time"

	"github.com/ethereum/go-ethereum/metrics"
)

var (
	// counter 자체는 인자 없이 생성
	counter = metrics.NewCounter()
	// 이름 붙이기는 Register로 따로
	_ = metrics.Register("my_metric", counter)

	mVerifyCount = metrics.NewCounter()
	_            = metrics.Register("hppk/verify/count", mVerifyCount)

	mVerifyFail = metrics.NewCounter()
	_           = metrics.Register("hppk/verify/fail", mVerifyFail)

	mVerifyDur = metrics.NewTimer()
	_          = metrics.Register("hppk/verify/duration", mVerifyDur)
)

func (pc *HPPKPrecompile) RunWithMetrics(input []byte) ([]byte, error) {
	start := time.Now()
	out, err := pc.Run(input)

	mVerifyDur.Update(time.Since(start))
	mVerifyCount.Inc(1)

	if err != nil || (len(out) == 1 && out[0] == 0) {
		mVerifyFail.Inc(1)
	}
	return out, err
}
