// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library HPPKPrecompile {
    address constant PRECOMPILE = address(0x0b);

    struct VerifyInput {
        bytes msgData;
        bytes sigF;
        bytes sigH;
        bytes[] pprime;
        bytes[] qprime;
        bytes[] mu;
        bytes[] nu;
        bytes s1p;
        bytes s2p;
    }

    function verify(VerifyInput memory v) internal view returns (bool ok) {
        // 주: geth쪽 Run()은 RLP 디코드이므로 실제 배포에서는 RLP 인코딩을 맞추세요.
        // 데모로는 abi.encode를 사용(실전: RLP 인코더 사용 권장)
        bytes memory payload = abi.encode(
            v.msgData, v.sigF, v.sigH, v.pprime, v.qprime, v.mu, v.nu, v.s1p, v.s2p
        );
        bytes memory out = new bytes(1);
        bool success;
        assembly {
            success := staticcall(gas(), PRECOMPILE, add(payload, 0x20), mload(payload), add(out, 0x20), 1)
        }
        return success && out[0] == 0x01;
    }
}
