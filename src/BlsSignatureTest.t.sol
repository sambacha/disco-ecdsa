// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.4;

import "./BlsSignatureVerification.sol";

contract BlsSignatureTest is BlsSignatureVerification {
    bool public verified;

    function verifySignature(
        bytes calldata _publicKey, // an E2 point
        bytes calldata _message,
        bytes calldata _signature // an E1 point
    ) external {
        E2Point memory pub = decodePublicKey(_publicKey);
        E1Point memory sig = decodeSignature(_signature);
        verified = verify(pub, _message, sig);
    }

    function decodePublicKey(bytes memory _pubKey)
        private
        pure
        returns (E2Point memory pubKey)
    {
        uint256[] memory output = new uint256[](4);
        for (uint256 i = 32; i <= output.length * 32; i += 32) {
            assembly {
                mstore(add(output, i), mload(add(_pubKey, i)))
            }
        }

        pubKey.x[0] = output[0];
        pubKey.x[1] = output[1];
        pubKey.y[0] = output[2];
        pubKey.y[1] = output[3];
    }

    function decodeSignature(bytes memory _sig)
        private
        pure
        returns (E1Point memory signature)
    {
        uint256[] memory output = new uint256[](2);
        for (uint256 i = 32; i <= output.length * 32; i += 32) {
            assembly {
                mstore(add(output, i), mload(add(_sig, i)))
            }
        }

        signature = E1Point(0, 0);
        signature.x = output[0];
        signature.y = output[1];
    }
}