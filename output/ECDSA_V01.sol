pragma solidity ^0.8.0<0.9.0;

import "./Strings_V01.sol";

///  @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
///  These functions can be used to verify that a message was signed by the holder
///  of the private keys of a given address.
library ECDSA {
  enum RecoverError { NoError, InvalidSignature, InvalidSignatureLength, InvalidSignatureS, InvalidSignatureV }

  function _throwError(RecoverError error) private pure {
    if (error == RecoverError.NoError) {
      return;
    } else if (error == RecoverError.InvalidSignature) {
      revert("ECDSA: invalid signature");
    } else if (error == RecoverError.InvalidSignatureLength) {
      revert("ECDSA: invalid signature length");
    } else if (error == RecoverError.InvalidSignatureS) {
      revert("ECDSA: invalid signature 's' value");
    }
  }

  ///  @dev Returns the address that signed a hashed message (`hash`) with
  ///  `signature` or error string. This address can then be used for verification purposes.
  ///  The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
  ///  this function rejects them by requiring the `s` value to be in the lower
  ///  half order, and the `v` value to be either 27 or 28.
  ///  IMPORTANT: `hash` _must_ be the result of a hash operation for the
  ///  verification to be secure: it is possible to craft signatures that
  ///  recover to arbitrary addresses for non-hashed data. A safe way to ensure
  ///  this is by receiving a hash of the original message (which may otherwise
  ///  be too long), and then calling {toEthSignedMessageHash} on it.
  ///  Documentation for signature generation:
  ///  - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
  ///  - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
  ///  _Available since v4.3._
  function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
    if (signature.length == 65) {
      bytes32 r;
      bytes32 s;
      uint8 v;
      /// @solidity memory-safe-assembly
      assembly {
        r := mload(add(signature, 0x20))
        s := mload(add(signature, 0x40))
        v := byte(0, mload(add(signature, 0x60)))
      }
      return tryRecover(hash, v, r, s);
    } else {
      return (address(0), RecoverError.InvalidSignatureLength);
    }
  }

  ///  @dev Returns the address that signed a hashed message (`hash`) with
  ///  `signature`. This address can then be used for verification purposes.
  ///  The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
  ///  this function rejects them by requiring the `s` value to be in the lower
  ///  half order, and the `v` value to be either 27 or 28.
  ///  IMPORTANT: `hash` _must_ be the result of a hash operation for the
  ///  verification to be secure: it is possible to craft signatures that
  ///  recover to arbitrary addresses for non-hashed data. A safe way to ensure
  ///  this is by receiving a hash of the original message (which may otherwise
  ///  be too long), and then calling {toEthSignedMessageHash} on it.
  function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
    (address recovered, RecoverError error) = tryRecover(hash, signature);
    _throwError(error);
    return recovered;
  }

  ///  @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
  ///  See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
  ///  _Available since v4.3._
  function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError) {
    bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
    uint8 v = uint8((uint256(vs) >> 255) + 27);
    return tryRecover(hash, v, r, s);
  }

  ///  @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
  ///  _Available since v4.2._
  function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
    (address recovered, RecoverError error) = tryRecover(hash, r, vs);
    _throwError(error);
    return recovered;
  }

  ///  @dev Overload of {ECDSA-tryRecover} that receives the `v`,
  ///  `r` and `s` signature fields separately.
  ///  _Available since v4.3._
  function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address, RecoverError) {
    if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
      return (address(0), RecoverError.InvalidSignatureS);
    }
    address signer = ecrecover(hash, v, r, s);
    if (signer == address(0)) {
      return (address(0), RecoverError.InvalidSignature);
    }
    return (signer, RecoverError.NoError);
  }

  ///  @dev Overload of {ECDSA-recover} that receives the `v`,
  ///  `r` and `s` signature fields separately.
  function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
    (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
    _throwError(error);
    return recovered;
  }

  ///  @dev Returns an Ethereum Signed Message, created from a `hash`. This
  ///  produces hash corresponding to the one signed with the
  ///  https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
  ///  JSON-RPC method as part of EIP-191.
  ///  See {recover}.
  function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {
    /// @solidity memory-safe-assembly
    assembly {
      mstore(0, "\u0019Ethereum Signed Message:\n32")
      mstore(28, hash)
      message := keccak256(0, 60)
    }
  }

  ///  @dev Returns an Ethereum Signed Message, created from `s`. This
  ///  produces hash corresponding to the one signed with the
  ///  https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
  ///  JSON-RPC method as part of EIP-191.
  ///  See {recover}.
  function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked("\u0019Ethereum Signed Message:\n", Strings.toString(s.length), s));
  }

  ///  @dev Returns an Ethereum Signed Typed Data, created from a
  ///  `domainSeparator` and a `structHash`. This produces hash corresponding
  ///  to the one signed with the
  ///  https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
  ///  JSON-RPC method as part of EIP-712.
  ///  See {recover}.
  function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 data) {
    /// @solidity memory-safe-assembly
    assembly {
      let ptr := mload(0x40)
      mstore(ptr, "\u0019\u0001")
      mstore(add(ptr, 0x02), domainSeparator)
      mstore(add(ptr, 0x22), structHash)
      data := keccak256(ptr, 66)
    }
  }
}