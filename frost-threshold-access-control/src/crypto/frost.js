// src/crypto/frost.js
const BN = require('bn.js');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1'); // Using the same curve as Ethereum
const { keccak256 } = require('ethers');

class FROST {
  constructor(t, n) {
    this.t = t; // Threshold
    this.n = n; // Total number of participants
    this.participants = new Map();
  }

  // Generate distributed key shares
  async generateShares() {
    // Implementation of polynomial secret sharing (Shamir's scheme)
    const secret = new BN(ec.genKeyPair().getPrivate().toString(10));
    const coefficients = [secret];
    
    // Generate random coefficients for polynomial
    for (let i = 1; i < this.t; i++) {
      coefficients.push(new BN(ec.genKeyPair().getPrivate().toString(10)));
    }

    // Generate shares for each participant
    for (let i = 1; i <= this.n; i++) {
      const x = new BN(i);
      let y = new BN(coefficients[0].toString(10));
      
      for (let j = 1; j < coefficients.length; j++) {
        const term = x.pow(new BN(j)).mul(coefficients[j]).mod(ec.n);
        y = y.add(term).mod(ec.n);
      }
      
      this.participants.set(i, {
        index: i,
        share: y,
        publicKey: ec.g.mul(y)
      });
    }

    // Calculate group public key
    this.groupPublicKey = ec.g.mul(secret);
    return {
      publicKey: this.groupPublicKey,
      shares: Array.from(this.participants.values())
    };
  }

  // FROST round 1: Generate commitments
  async generateCommitment(participantIndex) {
    if (!this.participants.has(participantIndex)) {
      throw new Error('Participant not found');
    }
    
    const participant = this.participants.get(participantIndex);
    const nonceSecret = new BN(ec.genKeyPair().getPrivate().toString(10));
    const noncePublic = ec.g.mul(nonceSecret);
    
    participant.nonce = {
      secret: nonceSecret,
      public: noncePublic
    };
    
    return {
      participantIndex,
      noncePublic
    };
  }

  // FROST round 2: Generate partial signatures and combine them
  async signMessage(message, participantIndices) {
    if (participantIndices.length < this.t) {
      throw new Error(`At least ${this.t} participants needed for signing`);
    }

    // Hash the message
    const messageHash = new BN(this._hashMessage(message), 16);
    
    // Collect partial signatures
    const partialSignatures = [];
    
    for (const index of participantIndices) {
      if (!this.participants.has(index)) {
        throw new Error(`Participant ${index} not found`);
      }
      
      const participant = this.participants.get(index);
      if (!participant.nonce) {
        throw new Error(`Participant ${index} has not generated commitment`);
      }
      
      // Calculate Lagrange coefficient
      const lambda = this._lagrangeCoefficient(index, participantIndices);
      
      // Calculate partial signature
      const share = participant.share;
      const k = participant.nonce.secret;
      
      // Signature contribution: s_i = k_i + c * x_i * lambda_i
      const partialSig = k.add(messageHash.mul(share).mul(lambda).mod(ec.n)).mod(ec.n);
      
      partialSignatures.push({
        index,
        signature: partialSig,
        noncePublic: participant.nonce.public
      });
    }
    
    // Combine partial signatures
    let combinedSignature = new BN(0);
    for (const partSig of partialSignatures) {
      combinedSignature = combinedSignature.add(partSig.signature).mod(ec.n);
    }
    
    // Get the combined nonce public key (R)
    let R = partialSignatures[0].noncePublic;
    for (let i = 1; i < partialSignatures.length; i++) {
      R = R.add(partialSignatures[i].noncePublic);
    }
    
    return {
      r: R.getX().toString(16),
      s: combinedSignature.toString(16),
      recoveryParam: R.getY().isOdd() ? 1 : 0
    };
  }

  // Verify a FROST signature
  async verifySignature(message, signature) {
    const messageHash = new BN(this._hashMessage(message), 16);
    const r = new BN(signature.r, 16);
    const s = new BN(signature.s, 16);
    const recoveryParam = signature.recoveryParam;
    
    // Signature verification: g^s = R * Y^h
    const left = ec.g.mul(s);
    
    // Reconstruct R point
    const rPoint = ec.curve.pointFromX(r, recoveryParam);
    const right = rPoint.add(this.groupPublicKey.mul(messageHash));
    
    return left.eq(right);
  }

  // Helper methods
  _hashMessage(message) {
    // Using keccak256 for hashing, similar to Ethereum
    return keccak256(Buffer.from(message)).slice(2); // remove 0x prefix
  }

  _lagrangeCoefficient(i, indices) {
    let num = new BN(1);
    let den = new BN(1);
    
    for (const j of indices) {
      if (i === j) continue;
      
      const jBN = new BN(j);
      const iBN = new BN(i);
      
      num = num.mul(jBN).mod(ec.n);
      den = den.mul(jBN.sub(iBN).mod(ec.n)).mod(ec.n);
    }
    
    return num.mul(den.invm(ec.n)).mod(ec.n);
  }
}

module.exports = FROST;