// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "./FROSTVerifier.sol";
import "./PolicyManager.sol";

/**
 * @title AccessControlCore
 * @notice Core contract for managing access control policies.
 * @dev This contract is upgradeable.
 */
contract AccessControlCore is Initializable, AccessControlUpgradeable {
    bytes32 public policyMerkleRoot;
    bool public circuitBreaker;
    FROSTVerifier public frostVerifier;
    PolicyManager public policyManager;

    mapping(bytes32 => bytes32) public roleMapping;

    event PolicyUpdated(bytes32 newMerkleRoot);
    event CircuitBreakerTripped(bool status);
    event RoleMapped(bytes32 role, bytes32 mappedRole);

    function initialize(address _frostVerifier, address _policyManager) public initializer {
        __AccessControl_init();
        frostVerifier = FROSTVerifier(_frostVerifier);
        policyManager = PolicyManager(_policyManager);
    }

    function checkAccess(
        bytes32 message,
        uint256 signatureR,
        uint256 signatureZ,
        EllipticCurve.Point memory groupPublicKey,
        bytes32[] calldata merkleProof,
        bytes32 leaf
    ) public view returns (bool) {
        if (circuitBreaker) {
            return false;
        }

        bool policyValid = policyManager.verifyPolicy(merkleProof, leaf);
        if (!policyValid) {
            return false;
        }

        bool signatureValid = frostVerifier.verify(message, signatureR, signatureZ, groupPublicKey);
        if (!signatureValid) {
            return false;
        }

        return true;
    }
}
