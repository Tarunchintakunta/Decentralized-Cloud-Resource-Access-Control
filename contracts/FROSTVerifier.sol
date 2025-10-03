// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

import "./EllipticCurve.sol";

/**
 * @title FROSTVerifier
 * @notice Verifies FROST Schnorr signatures on the secp256k1 curve.
 * @dev This contract uses a pre-existing Schnorr verification library and adapts it for FROST.
 */
contract FROSTVerifier {
    /**
     * @notice Verifies a FROST Schnorr signature.
     * @param message The message that was signed.
     * @param signatureR The R component of the signature.
     * @param signatureZ The z component of the signature.
     * @param groupPublicKey The aggregated public key of the signing group.
     * @return True if the signature is valid, false otherwise.
     */
    function verify(
        bytes32 message,
        uint256 signatureR,
        uint256 signatureZ,
        EllipticCurve.Point memory groupPublicKey
    ) public view returns (bool) {
        require(EllipticCurve.isOnCurve(groupPublicKey), "Invalid public key");
        require(signatureR > 0 && signatureR < EllipticCurve.p(), "Invalid signature R");
        require(signatureZ > 0 && signatureZ < EllipticCurve.n(), "Invalid signature Z");

        EllipticCurve.Point memory R = EllipticCurve.decompress(signatureR);
        bytes32 challenge = keccak256(abi.encodePacked(R.x, R.y, groupPublicKey.x, groupPublicKey.y, message));

        EllipticCurve.Point memory Gz = EllipticCurve.mul(EllipticCurve.g(), signatureZ);
        EllipticCurve.Point memory RcPk = EllipticCurve.add(R, EllipticCurve.mul(groupPublicKey, uint256(challenge)));

        return Gz.x == RcPk.x && Gz.y == RcPk.y;
    }
}
