const FROST = artifacts.require("FROSTAccessControl");
const FROSTJs = require('../src/crypto/frost');
const chai = require('chai');
const assert = chai.assert;

describe('FROST Threshold Signature', () => {
  const threshold = 2;
  const totalParticipants = 3;
  
  let frost;
  
  beforeEach(async () => {
    frost = new FROSTJs(threshold, totalParticipants);
  });
  
  it('should generate shares correctly', async () => {
    const result = await frost.generateShares();
    
    // Verify the results
    assert.property(result, 'publicKey', 'Result should have a publicKey');
    assert.property(result, 'shares', 'Result should have shares');
    assert.equal(result.shares.length, totalParticipants, 'Should generate correct number of shares');
    
    // Verify each share
    for (let i = 0; i < result.shares.length; i++) {
      const share = result.shares[i];
      assert.property(share, 'index', 'Share should have an index');
      assert.property(share, 'share', 'Share should have a share value');
      assert.property(share, 'publicKey', 'Share should have a publicKey');
    }
  });
  
  it('should generate commitments correctly', async () => {
    // First generate shares
    await frost.generateShares();
    
    // Generate a commitment for participant 1
    const commitment = await frost.generateCommitment(1);
    
    assert.property(commitment, 'participantIndex', 'Commitment should have a participant index');
    assert.property(commitment, 'noncePublic', 'Commitment should have a public nonce');
    assert.equal(commitment.participantIndex, 1, 'Commitment should be for the correct participant');
  });
  
  it('should sign and verify a message correctly with threshold signers', async () => {
    // Generate shares
    await frost.generateShares();
    
    // Generate commitments for all participants
    for (let i = 1; i <= totalParticipants; i++) {
      await frost.generateCommitment(i);
    }
    
    // Choose t participants to sign
    const participantIndices = [1, 2]; // threshold = 2
    const message = 'Hello, FROST!';
    
    // Sign the message
    const signature = await frost.signMessage(message, participantIndices);
    
    // Verify properties
    assert.property(signature, 'r', 'Signature should have r component');
    assert.property(signature, 's', 'Signature should have s component');
    
    // Verify the signature
    const isValid = await frost.verifySignature(message, signature);
    assert.isTrue(isValid, 'Signature should be valid');
  });
  
  it('should reject signing with fewer than threshold participants', async () => {
    // Generate shares
    await frost.generateShares();
    
    // Generate commitments
    await frost.generateCommitment(1);
    
    // Try to sign with just 1 participant (threshold is 2)
    const participantIndices = [1];
    const message = 'Hello, FROST!';
    
    try {
      await frost.signMessage(message, participantIndices);
      assert.fail('Should have thrown an error');
    } catch (error) {
      assert.include(error.message, 'participants needed', 'Error should mention threshold');
    }
  });
  
  it('should successfully verify a different message with threshold signers', async () => {
    // Generate shares
    await frost.generateShares();
    
    // Generate commitments for all participants
    for (let i = 1; i <= totalParticipants; i++) {
      await frost.generateCommitment(i);
    }
    
    // Choose different participants to sign
    const participantIndices = [2, 3]; // Still meeting threshold = 2
    const message = 'Different message for FROST!';
    
    // Sign the message
    const signature = await frost.signMessage(message, participantIndices);
    
    // Verify the signature
    const isValid = await frost.verifySignature(message, signature);
    assert.isTrue(isValid, 'Signature should be valid');
  });
});