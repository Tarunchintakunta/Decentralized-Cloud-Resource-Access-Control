import { secp256k1 } from '@noble/curves/secp256k1';
import { mod } from '@noble/curves/abstract/modular';
import { sha256 } from '@noble/hashes/sha256';

const Ciphersuite = {
    ID: 'FROST_secp256k1_SHA256',
    CONTEXT: 'FROST_secp256k1_SHA256_CONTEXT',
    q: secp256k1.CURVE.n,
    G: secp256k1.ProjectivePoint.BASE,
};

type Participant = {
    id: bigint;
    coefficients: bigint[];
    proofOfKnowledge: [bigint, bigint];
    publicKey: secp256k1.ProjectivePoint;
    secretShare?: bigint;
    nonce?: [bigint, bigint];
    signatureShare?: bigint;
};

type Round1Output = {
    commitments: [secp256k1.ProjectivePoint, secp256k1.ProjectivePoint][];
};

type Round2Output = {
    signatureShares: bigint[];
};

type AggregatedSignature = {
    R: secp256k1.ProjectivePoint;
    z: bigint;
};

// Helper function to generate a random number within the finite field
const getRandomNumber = () => mod(BigInt(`0x${Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex')}`), Ciphersuite.q);

/**
 * Creates a new participant for the FROST protocol.
 * @param id The participant's identifier.
 * @param t The threshold of signers required.
 * @returns A new participant.
 */
export function createParticipant(id: bigint, t: number): Participant {
    const coefficients = Array.from({ length: t }, (_, i) => {
        const key = i === 0 ? secp256k1.utils.randomPrivateKey() : secp256k1.utils.randomPrivateKey();
        return BigInt(`0x${Buffer.from(key).toString('hex')}`);
    });

    const secret = coefficients[0];
    const proofOfKnowledge = schnorrProve(secret);
    const publicKey = Ciphersuite.G.multiply(secret);

    return {
        id,
        coefficients,
        proofOfKnowledge,
        publicKey,
    };
}

/**
 * Generates a Schnorr proof of knowledge of a secret key.
 * @param secret The secret key.
 * @returns A tuple containing the nonce and the signature.
 */
function schnorrProve(secret: bigint): [bigint, bigint] {
    const r = BigInt(`0x${Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex')}`);
    const R = Ciphersuite.G.multiply(r);
    const P = Ciphersuite.G.multiply(secret);
    const c = challenge(P, R);
    const s = mod(r + c * secret, Ciphersuite.q);
    return [BigInt(`0x${Buffer.from(R.toRawBytes()).toString('hex')}`), s];
}

/**
 * Computes the challenge hash for a Schnorr proof.
 * @param P The public key.
 * @param R The nonce point.
 * @returns The challenge hash.
 */
function challenge(
    P: secp256k1.ProjectivePoint,
    R: secp256k1.ProjectivePoint,
    message?: Uint8Array
): bigint {
    const PBytes = P.toRawBytes();
    const RBytes = R.toRawBytes();
    const MBytes = message || new Uint8Array();
    const msg = new Uint8Array(PBytes.length + RBytes.length + MBytes.length);
    msg.set(PBytes);
    msg.set(RBytes, PBytes.length);
    msg.set(MBytes, PBytes.length + RBytes.length);
    return BigInt(`0x${Buffer.from(sha256(msg)).toString('hex')}`);
}

/**
 * Calculates the secret share for a given participant.
 * @param coefficients The coefficients of the polynomial.
 * @param id The identifier of the participant to calculate the share for.
 * @returns The secret share.
 */
export function calculateSecretShare(coefficients: bigint[], id: bigint): bigint {
    let share = 0n;
    for (let i = 0; i < coefficients.length; i++) {
        share = mod(share + coefficients[i] * (id ** BigInt(i)), Ciphersuite.q);
    }
    return share;
}

/**
 * Verifies a secret share against a participant's public key.
 * @param share The secret share to verify.
 * @param publicKey The public key of the participant who sent the share.
 * @param id The identifier of the participant receiving the share.
 * @returns True if the share is valid, false otherwise.
 */
export function verifySecretShare(share: bigint, publicKey: secp256k1.ProjectivePoint, id: bigint): boolean {
    const Gs = Ciphersuite.G.multiply(share);
    // This is a simplified check. A full DKG would require commitment verification.
    return Gs.equals(publicKey.multiply(id));
}

/**
 * Aggregates the public keys of a set of participants.
 * @param publicKeys An array of public keys.
 * @returns The aggregated public key.
 */
export function aggregatePublicKeys(publicKeys: secp256k1.ProjectivePoint[]): secp256k1.ProjectivePoint {
    return publicKeys.reduce((acc, pk) => acc.add(pk), secp256k1.ProjectivePoint.ZERO);
}

/**
 * Executes the first round of the FROST signing protocol.
 * @param participant The participant executing the round.
 * @returns The commitments to be broadcasted.
 */
export function signRound1(participant: Participant): [secp256k1.ProjectivePoint, secp256k1.ProjectivePoint] {
    const d = BigInt(`0x${Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex')}`);
    const e = BigInt(`0x${Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex')}`);
    participant.nonce = [d, e];
    const D = Ciphersuite.G.multiply(d);
    const E = Ciphersuite.G.multiply(e);
    return [D, E];
}

/**
 * Executes the second round of the FROST signing protocol.
 * @param participant The participant executing the round.
 * @param message The message to sign.
 * @param commitments An array of commitments from all participants.
 * @param groupPublicKey The aggregated public key of the group.
 * @returns The participant's signature share.
 */
export function signRound2(
    participant: Participant,
    message: Uint8Array,
    commitments: [secp256k1.ProjectivePoint, secp256k1.ProjectivePoint][],
    groupPublicKey: secp256k1.ProjectivePoint
): bigint {
    if (!participant.nonce || !participant.secretShare) {
        throw new Error('Participant has not completed round 1 or DKG');
    }

    const R = commitments.reduce((acc, c) => acc.add(c[0]), secp256k1.ProjectivePoint.ZERO);
    const c = challenge(groupPublicKey, R, message);

    const lambda_i = lagrange(participant.id, commitments.map((_, i) => BigInt(i + 1)));
    const z_i = mod(participant.nonce[0] + participant.nonce[1] * c, Ciphersuite.q);

    return mod(z_i + lambda_i * participant.secretShare * c, Ciphersuite.q);
}

/**
 * Aggregates the signature shares from a set of participants.
 * @param signatureShares An array of signature shares.
 * @returns The aggregated signature.
 */
export function aggregateSignatures(
    signatureShares: bigint[],
    commitments: [secp256k1.ProjectivePoint, secp256k1.ProjectivePoint][],
    groupPublicKey: secp256k1.ProjectivePoint,
    message: Uint8Array
): AggregatedSignature {
    const z = signatureShares.reduce((acc, s) => mod(acc + s, Ciphersuite.q), 0n);
    const R = commitments.reduce((acc, c) => acc.add(c[0]), secp256k1.ProjectivePoint.ZERO);
    const c = challenge(groupPublicKey, R, message);

    // Verify the aggregated signature
    const Gz = Ciphersuite.G.multiply(z);
    const RcPk = R.add(groupPublicKey.multiply(c));
    if (!Gz.equals(RcPk)) {
        throw new Error('Aggregated signature is invalid');
    }

    return { R, z };
}

/**
 * Calculates the Lagrange coefficient for a given participant.
 * @param i The identifier of the participant.
 * @param S The set of participant identifiers.
 * @returns The Lagrange coefficient.
 */
function lagrange(i: bigint, S: bigint[]): bigint {
    let num = 1n;
    let den = 1n;
    for (const j of S) {
        if (i === j) continue;
        num = mod(num * j, Ciphersuite.q);
        den = mod(den * (j - i), Ciphersuite.q);
    }
    return mod(num * modInverse(den, Ciphersuite.q), Ciphersuite.q);
}

/**
 * Computes the modular inverse of a number.
 * @param n The number.
 * @param p The modulus.
 * @returns The modular inverse.
 */
function modInverse(n: bigint, p: bigint): bigint {
    return modPow(n, p - 2n, p);
}

/**
 * Computes the modular exponentiation of a number.
 * @param base The base.
 * @param exp The exponent.
 * @param mod The modulus.
 * @returns The result of the modular exponentiation.
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        exp = exp >> 1n;
        base = (base * base) % mod;
    }
    return res;
}
