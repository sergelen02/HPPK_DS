// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


interface IFHE {
function keygen() external returns (bytes memory pkHandle);
function enc(bytes memory pkHandle, bytes memory m) external view returns (bytes memory ct);
function dec(bytes memory ct) external returns (bytes memory m);
function add(bytes memory ct1, bytes memory ct2) external view returns (bytes memory ct);
function mul(bytes memory ct1, bytes memory ct2) external view returns (bytes memory ct);
}


library FHEPrecompile {
address constant PRECOMPILE = address(0x0c); // 예시: FHE 전용 주소


function _call(bytes memory payload) private view returns (bytes memory out) {
out = new bytes(0x2000);
bool ok;
assembly {
ok := staticcall(gas(), PRECOMPILE, add(payload,0x20), mload(payload), add(out,0x20), 0x2000)
}
require(ok, "FHE precompile call failed");
}


// 아래 함수들은 프리컴파일 ABI(또는 RLP)에 맞춰 payload를 구성해야 합니다.
function keygen() internal view returns (bytes memory pkHandle) { pkHandle = _call(abi.encode("keygen")); }
function enc(bytes memory pk, bytes memory m) internal view returns (bytes memory ct) { ct = _call(abi.encode("enc", pk, m)); }
function add(bytes memory a, bytes memory b) internal view returns (bytes memory ct) { ct = _call(abi.encode("add", a, b)); }
function mul(bytes memory a, bytes memory b) internal view returns (bytes memory ct) { ct = _call(abi.encode("mul", a, b)); }
}