const FROST = require('./crypto/frost');

async function runDemo() {
  console.log('FROST Threshold Signature Demo');
  console.log('================================');
  
  // Create a 2-of-3 threshold scheme
  const t = 2;
  const n = 3;
  console.log(`Creating ${t}-of-${n} threshold scheme...`);
  
  const frost = new FROST(t, n);
  
  // Generate key shares
  console.log('\nGenerating key shares...');
  const { publicKey, shares } = await frost.generateShares();
  
  console.log(`Group public key: ${publicKey.encode('hex')}`);
  console.log('Individual shares:');
  shares.forEach(share => {
    console.log(`  Participant ${share.index}: ${share.share.toString(16).slice(0, 8)}...`);
  });
  
  // Generate commitments (round 1)
  console.log('\nRound 1: Generating commitments...');
  for (let i = 1; i <= n; i++) {
    const commitment = await frost.generateCommitment(i);
    console.log(`  Participant ${i} commitment: ${commitment.noncePublic.encode('hex').slice(0, 16)}...`);
  }
  
  // Sign a message (round 2)
  console.log('\nRound 2: Signing message...');
  const message = 'This is a test message for FROST threshold signature';
  console.log(`Message: "${message}"`);
  
  // Use participants 1 and 3 for signing (meeting the threshold t=2)
  const signers = [1, 3];
  console.log(`Signers: ${signers.join(', ')}`);
  
  const signature = await frost.signMessage(message, signers);
  console.log(`Signature: r=${signature.r.slice(0, 16)}..., s=${signature.s.slice(0, 16)}...`);
  
  // Verify the signature
  console.log('\nVerifying signature...');
  const isValid = await frost.verifySignature(message, signature);
  console.log(`Signature valid: ${isValid}`);
  
  // Try with a different message
  const wrongMessage = 'This is a DIFFERENT message';
  const wrongValid = await frost.verifySignature(wrongMessage, signature);
  console.log(`Verification with wrong message: ${wrongValid}`);
}

runDemo().catch(console.error);