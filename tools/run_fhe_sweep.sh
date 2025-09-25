#!/usr/bin/env bash
# 입력 범위와 반복 깊이를 바꿔가며 Go 테스트를 반복 실행
set -euo pipefail


SIZES=(32 64 128 256) # 비트 길이 또는 값 범주
DEPTHS_ADD=(1 2 4 8 16 32)
DEPTHS_MUL=(1 2 4 8)


for s in "${SIZES[@]}"; do
for d in "${DEPTHS_ADD[@]}"; do
echo "[ADD] size=$s depth=$d"
go test ./go/fhe -run TestHomomorphicAddMul -v -args -size=$s -adddepth=$d | tee -a results/fhe_sweep.log
done
for d in "${DEPTHS_MUL[@]}"; do
echo "[MUL] size=$s depth=$d"
go test ./go/fhe -run TestHomomorphicAddMul -v -args -size=$s -muldepth=$d | tee -a results/fhe_sweep.log
done
done