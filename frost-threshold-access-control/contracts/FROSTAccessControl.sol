// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";


/**
 * @title FROSTAccessControl
 * @dev Smart contract for decentralized cloud resource access control using FROST threshold signatures
 */
 
contract FROSTAccessControl is AccessControl, Pausable, Initializable {
    using ECDSA for bytes32;

    // Define roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 public constant CLOUD_RESOURCE_ROLE = keccak256("CLOUD_RESOURCE_ROLE");

    // Storage optimization: pack related variables together
    struct ThresholdConfig {
        uint16 threshold;        // Minimum signers required (using uint16 saves gas)
        uint16 totalSigners;     // Total number of possible signers
        uint32 lastUpdated;      // Timestamp of last threshold update
    }

    struct ResourceAccess {
        bool isActive;           // Is the resource currently accessible
        uint32 expirationTime;   // When does the access expire
        uint32 lastAccessed;     // When was the resource last accessed
        address resourceId;      // Address identifier for the resource
    }

    // Main storage variables
    ThresholdConfig public config;
    mapping(bytes32 => ResourceAccess) private resourceAccess; // Resource ID => Access info
    mapping(bytes32 => bool) private usedSignatures; // Signature hash => used status (prevent replay)
    
    // Group public key for FROST verification
    bytes public groupPublicKey;

    // Events
    event AccessGranted(bytes32 indexed resourceId, address indexed requester, uint256 validUntil);
    event AccessRevoked(bytes32 indexed resourceId, address indexed requester);
    event ThresholdChanged(uint16 oldThreshold, uint16 newThreshold);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event GroupPublicKeyUpdated(bytes newGroupPublicKey);

    /**
     * @dev Constructor to set initial threshold and admin
     * @param _initialAdmin Initial admin address
     * @param _threshold Initial threshold value
     * @param _signers Array of initial signers
     * @param _groupPubKey FROST group public key
     */
    constructor(
        address _initialAdmin,
        uint16 _threshold,
        address[] memory _signers,
        bytes memory _groupPubKey
    ) {
        require(_threshold > 0 && _threshold <= _signers.length, "Invalid threshold");
        
        _grantRole(ADMIN_ROLE, _initialAdmin);
        _setRoleAdmin(SIGNER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(CLOUD_RESOURCE_ROLE, ADMIN_ROLE);

        // Set up initial configuration
        config = ThresholdConfig({
            threshold: _threshold,
            totalSigners: uint16(_signers.length),
            lastUpdated: uint32(block.timestamp)
        });

        // Add initial signers
        for (uint i = 0; i < _signers.length; i++) {
            _grantRole(SIGNER_ROLE, _signers[i]);
        }

        // Set group public key
        groupPublicKey = _groupPubKey;
    }

    /**
     * @dev Update threshold value (admin only)
     * @param _newThreshold New threshold value
     */
    function updateThreshold(uint16 _newThreshold) external onlyRole(ADMIN_ROLE) {
        require(_newThreshold > 0 && _newThreshold <= config.totalSigners, "Invalid threshold");
        
        uint16 oldThreshold = config.threshold;
        config.threshold = _newThreshold;
        config.lastUpdated = uint32(block.timestamp);
        
        emit ThresholdChanged(oldThreshold, _newThreshold);
    }

    /**
     * @dev Add a new signer (admin only)
     * @param _signer Address of the new signer
     */
    function addSigner(address _signer) external onlyRole(ADMIN_ROLE) {
        require(!hasRole(SIGNER_ROLE, _signer), "Already a signer");
        
        _grantRole(SIGNER_ROLE, _signer);
        config.totalSigners += 1;
        config.lastUpdated = uint32(block.timestamp);
        
        emit SignerAdded(_signer);
    }

    /**
     * @dev Remove a signer (admin only)
     * @param _signer Address of the signer to remove
     */
    function removeSigner(address _signer) external onlyRole(ADMIN_ROLE) {
        require(hasRole(SIGNER_ROLE, _signer), "Not a signer");
        require(config.totalSigners > config.threshold, "Cannot have fewer signers than threshold");
        
        _revokeRole(SIGNER_ROLE, _signer);
        config.totalSigners -= 1;
        config.lastUpdated = uint32(block.timestamp);
        
        emit SignerRemoved(_signer);
    }

    /**
     * @dev Update the group public key (admin only)
     * @param _newGroupPubKey New FROST group public key
     */
    function updateGroupPublicKey(bytes calldata _newGroupPubKey) external onlyRole(ADMIN_ROLE) {
        groupPublicKey = _newGroupPubKey;
        emit GroupPublicKeyUpdated(_newGroupPubKey);
    }

    /**
     * @dev Request access to a cloud resource using FROST signature
     * @param _resourceId ID of the requested resource
     * @param _requester Address requesting access
     * @param _validUntil Timestamp when access should expire
     * @param _signature FROST signature (r,s) for the request
     * @param _messageHash Hash of the signed message
     * @param _v Recovery ID for signature verification
     */
    function requestAccess(
        bytes32 _resourceId,
        address _requester,
        uint32 _validUntil,
        bytes calldata _signature,
        bytes32 _messageHash,
        uint8 _v
    ) external whenNotPaused {
        // Check that the resource exists
        require(_requester != address(0), "Invalid requester");
        require(_validUntil > block.timestamp, "Invalid expiration time");

        // Prevent signature reuse
        bytes32 signatureHash = keccak256(_signature);
        require(!usedSignatures[signatureHash], "Signature already used");
        usedSignatures[signatureHash] = true;

        // Verify the message hash matches the request parameters
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "ACCESS_REQUEST", 
            _resourceId, 
            _requester, 
            _validUntil
        ));
        require(_messageHash == expectedHash, "Invalid message hash");

        // Verify FROST signature - This would be a complex FROST verification
        // Here we're using a simplified ECDSA verification with recovery
        address recoveredSigner = _messageHash.recover(abi.encodePacked(_signature, bytes1(_v)));
        require(hasRole(SIGNER_ROLE, recoveredSigner), "Invalid signature");

        // Grant access to the resource
        resourceAccess[_resourceId] = ResourceAccess({
            isActive: true,
            expirationTime: _validUntil,
            lastAccessed: uint32(block.timestamp),
            resourceId: _requester
        });

        emit AccessGranted(_resourceId, _requester, _validUntil);
    }

    /**
     * @dev Check if a requester has access to a resource
     * @param _resourceId ID of the resource
     * @param _requester Address of the requester
     * @return bool True if access is granted
     */
    function hasAccess(bytes32 _resourceId, address _requester) public view returns (bool) {
        ResourceAccess storage access = resourceAccess[_resourceId];
        
        return access.isActive && 
               access.resourceId == _requester && 
               access.expirationTime > block.timestamp;
    }

    /**
     * @dev Revoke access to a resource (admin only)
     * @param _resourceId ID of the resource
     */
    function revokeAccess(bytes32 _resourceId) external onlyRole(ADMIN_ROLE) {
        require(resourceAccess[_resourceId].isActive, "Access not active");
        
        address requester = resourceAccess[_resourceId].resourceId;
        resourceAccess[_resourceId].isActive = false;
        
        emit AccessRevoked(_resourceId, requester);
    }

    /**
     * @dev Pause the contract (emergency only)
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @dev Unpause the contract
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}