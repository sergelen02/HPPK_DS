// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


import "forge-std/Test.sol";
import {FHEPrecompile} from "../contracts/HPPKFHE.sol";


contract FHETest is Test {
function test_AddMulHomomorphism() public view {
bytes memory pk = FHEPrecompile.keygen();


// 예시 평문 (고정 길이 숫자 직렬화 규칙 필요)
bytes memory m1 = abi.encode(uint256(12345));
bytes memory m2 = abi.encode(uint256(6789));


bytes memory c1 = FHEPrecompile.enc(pk, m1);
bytes memory c2 = FHEPrecompile.enc(pk, m2);


// Add
bytes memory cAdd = FHEPrecompile.add(c1, c2);
bytes memory mAdd = FHEPrecompile._call(abi.encode("dec", cAdd));
// 평문 덧셈과 비교 (decode 규칙 필요)
uint256 gotAdd = abi.decode(mAdd, (uint256));
assertEq(gotAdd, 12345 + 6789);


// Mul
bytes memory cMul = FHEPrecompile.mul(c1, c2);
bytes memory mMul = FHEPrecompile._call(abi.encode("dec", cMul));
uint256 gotMul = abi.decode(mMul, (uint256));
assertEq(gotMul, 12345 * 6789);
}
}