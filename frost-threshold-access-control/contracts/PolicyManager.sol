// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "./AccessControlCore.sol";

/**
 * @title PolicyManager
 * @notice Manages Merkle-tree based permission proofs.
 */
contract PolicyManager {
    AccessControlCore public accessControlCore;

    constructor(address _accessControlCore) {
        accessControlCore = AccessControlCore(_accessControlCore);
    }

    function verifyPolicy(bytes32[] calldata merkleProof, bytes32 leaf) public view returns (bool) {
        bytes32 root = accessControlCore.policyMerkleRoot();
        return MerkleProof.verify(merkleProof, root, leaf);
    }
}
