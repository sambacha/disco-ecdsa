// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.4;

import "./ECDSA_SignatureVerification.sol";

contract EcdsaSignatureTest is EcdsaSignatureVerification {
    function verify2(
        address _signer,
        bytes calldata _message,
        bytes calldata _signature
    ) external pure returns (bool) {
        return verify(_signer, _message, _signature);
    }

    function verifySigComponents2(
        address _signer,
        bytes calldata _message,
        bytes32 _sigR,
        bytes32 _sigS,
        uint8 _sigV
    ) external pure returns (bool) {
        return verifySigComponents(_signer, _message, _sigR, _sigS, _sigV);
    }
}