/// SPDX-License-Identifer: UPL or MIT

pragma solidity ^0.8.17 <0.9.0;

/*
 * {@link https://entethalliance.github.io/crosschain-interoperability/draft_crosschain_techspec_messaging.html }
 *
 */

/// @title SignatureEncoding

contract SignatureEncoding {
    uint256 public constant ECDSA_SIGNATURE = 1;

    struct Signature {
        address by;
        bytes32 sigR;
        bytes32 sigS;
        uint8 sigV;
        bytes meta;
    }

    struct Signatures {
        uint256 typ;
        Signature[] signatures;
    }

    /**
     *
     *  ✓ decodeSignature
     * 
     *  Decode a signature blob.
     *
     * @param _signatures Encoded signatures.
     * @return Signture object.
     * 
     */
    function decodeSignature(bytes calldata _signatures)
        internal
        pure
        returns (Signatures memory)
    {
        (
            ,
        /* Skip offset of dynamic type */
            uint256 sigType
        ) = abi.decode(_signatures, (uint256, uint256));
        require(sigType == ECDSA_SIGNATURE, "Signature unknown type");

        Signatures memory sigs = abi.decode(_signatures, (Signatures));
        return sigs;
    }
}
