// SPDX-License-Identifier: MIT
// Author: vectorized.eth
pragma solidity ^0.8.0;
pragma abicoder v2;


/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol)
library ECDSA {
    
    function recover(bytes32 hash, bytes calldata signature) internal view returns (address result) {
        assembly {
            // Copy the free memory pointer so that we can restore it later.
            let m := mload(0x40)

            // Directly load the fields from the calldata.
            let s := calldataload(add(signature.offset, 0x20))
            // If `signature.length == 65`, but just do it anyway as it costs less gas than a switch.
            let v := byte(0, calldataload(add(signature.offset, 0x40)))

            // If `signature.length == 64`.
            if iszero(sub(signature.length, 64)) {
                // Here, `s` is actually `vs` that needs to be recovered into `v` and `s`.
                v := add(shr(255, s), 27)
                // prettier-ignore
                s := and(s, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
            }

            // If signature is valid and not malleable.
            if and(
                // `s` in lower half order.
                // prettier-ignore
                lt(s, 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1),
                // `v` is 27 or 28
                byte(v, 0x0101000000)
            ) {
                mstore(0x00, hash)
                mstore(0x20, v)
                calldatacopy(0x40, signature.offset, 0x20) // Directly copy `r` over.
                mstore(0x60, s)
                let success := staticcall(
                    gas(), // Amount of gas left for the transaction.
                    0x01, // Address of `ecrecover`.
                    0x00, // Start of input.
                    0x80, // Size of input.
                    0x40, // Start of output.
                    0x20 // Size of output.
                )
                // Restore the zero slot.
                mstore(0x60, 0)
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                result := mload(sub(0x60, mul(returndatasize(), success)))
            }
            // Restore the free memory pointer.
            mstore(0x40, m)
        }
    }

    // It is actually more efficient to sign bytes32 than bytes, because the latter
    // requires the signature prefix to include the decimal string of the 
    // bytes' length, which is more expensive to compute than one more keccak256.
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        assembly {
            // Store into scratch space for keccak256.
            mstore(0x20, hash)
            mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32")
            // 0x40 - 0x04 = 0x3c
            result := keccak256(0x04, 0x3c)
        }
    }

    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32 result) {
        assembly {
            let ptr := add(mload(0x40), 128)
            
            let mid := ptr
            let sLength := mload(s)
            let end := add(mid, sLength)

            // Update the free memory pointer to allocate.
            mstore(0x40, shl(5, add(1, shr(5, end))))
            
            for {
                let temp := sLength
                ptr := sub(ptr, 1)
                mstore8(ptr, add(48, mod(temp, 10))) 
                temp := div(temp, 10)
            } temp {
                temp := div(temp, 10)
            } {
                ptr := sub(ptr, 1)
                mstore8(ptr, add(48, mod(temp, 10)))
            }

            // Move the pointer 32 bytes lower to make room for the prefix.
            let start := sub(ptr, 32)
            // Store the signature prefix.
            mstore(start, "\x00\x00\x00\x00\x00\x00\x19Ethereum Signed Message:\n")
            start := add(start, 6)

            for {
                let temp := add(s, 0x20)
                ptr := mid 
            } lt(ptr, end) { 
                ptr := add(ptr, 0x20) 
            } {
                mstore(ptr, mload(temp))
                temp := add(temp, 0x20) 
            }
            result := keccak256(start, sub(end, start))
        }
    }
}

library LibString {
    
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory str) {
        assembly {
            let start := mload(0x40)
            // We need 1 32-byte word for the length, 1 32-byte word for the prefix,
            // and 2 32-byte words for the digits, totaling to 128 bytes. 
            // But if a custom length is provided, we will ensure there is minimally enough space, 
            // with the free memory pointer rounded up to a multiple of 32.
            str := add(start, add(128, shl(6, shr(5, length))))

            // Cache the end to calculate the length later.
            let end := str

            // Allocate the memory.
            mstore(0x40, str) 

            // We write the string from rightmost digit to leftmost digit.
            // The following is essentially a do-while loop that also handles the zero case.
            // Costs a bit more vs early return for the zero case, 
            // but otherwise cheaper in terms of deployment and overall runtime costs.
            for { 
                // Initialize and perform the first pass without check.
                let temp := value
                str := sub(str, 1)
                mstore8(str, byte(and(temp, 15), "0123456789abcdef"))
                temp := shr(4, temp)
                str := sub(str, 1)
                mstore8(str, byte(and(temp, 15), "0123456789abcdef"))
                temp := shr(4, temp)
                length := sub(length, gt(length, 0))
            } or(length, temp) { 
                length := sub(length, gt(length, 0))
            } { 
                str := sub(str, 1)
                mstore8(str, byte(and(temp, 15), "0123456789abcdef"))
                temp := shr(4, temp)
                str := sub(str, 1)
                mstore8(str, byte(and(temp, 15), "0123456789abcdef"))
                temp := shr(4, temp)
            }

            // Compute the string's length.
            let strLength := add(sub(end, str), 2)
            // Move the pointer and write the "0x" prefix, which is 0x3078.
            str := sub(str, 32)
            mstore(str, 0x3078) 
            // Move the pointer and write the length.
            str := sub(str, 2)
            mstore(str, strLength)
        }
    }

    function toHexString(uint256 value) internal pure returns (string memory str) {
        str = toHexString(value, 0);
    }

    function toHexString(address value) internal pure returns (string memory str) {
        str = toHexString(value, 20);
    }
}
