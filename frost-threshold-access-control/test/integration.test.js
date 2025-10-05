const FROSTAccessControl = artifacts.require("FROSTAccessControl");
const FROST = require('../src/crypto/frost');
const { expectRevert } = require('@openzeppelin/test-helpers');
const { web3 } = require('@openzeppelin/test-helpers/src/setup');
const { solidityPackedKeccak256 } = require('ethers');

contract("Integration Test", accounts => {
  const admin = accounts[0];
  const signer1 = accounts[1];
  const signer2 = accounts[2];
  const signer3 = accounts[3];
  const requester = accounts[4];
  
  const threshold = 2;
  const totalParticipants = 3;
  const initialSigners = [signer1, signer2, signer3];
  
  let accessControl;
  let frost;
  let resourceId;
  let groupPublicKeyHex;
  
  beforeEach(async () => {
    // Initialize FROST
    frost = new FROST(threshold, totalParticipants);
    
    // Generate key shares
    const keyData = await frost.generateShares();
    groupPublicKeyHex = "0x" + keyData.publicKey.encode('hex');
    
    // Deploy the smart contract
    accessControl = await FROSTAccessControl.new(
      admin,
      threshold,
      initialSigners,
      groupPublicKeyHex
    );
    
    // Generate a random resource ID
    resourceId = web3.utils.keccak256("Resource" + Math.random().toString());
    
    // Generate commitments for all participants
    for (let i = 1; i <= totalParticipants; i++) {
      await frost.generateCommitment(i);
    }
  });
  
  it("should grant access with valid FROST signature", async () => {
    // Create message for signing
    const validUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    
    const message = solidityPackedKeccak256(
      ['string', 'bytes32', 'address', 'uint32'],
      ['ACCESS_REQUEST', resourceId, requester, validUntil]
    ).slice(2); // Remove '0x' prefix
    
    // Sign with FROST (participants 1 and 2)
    const signers = [1, 2];
    const signature = await frost.signMessage(message, signers);
    
    // Convert signature to format expected by the contract
    const sigBytes = Buffer.from(signature.r + signature.s, 'hex');
    const v = 27 + signature.recoveryParam;
    
    // Request access through the smart contract
    await accessControl.requestAccess(resourceId, requester, validUntil, sigBytes, "0x" + message, v);

    // Check access after request
    const accessAfter = await accessControl.hasAccess(resourceId, requester);
    assert.equal(accessAfter, true, "Should have access after request");
  });
});