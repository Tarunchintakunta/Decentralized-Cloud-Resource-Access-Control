import { ec } from "elliptic";
import { sha256 } from "hash.js";
import BN from "bn.js";
import { ethers } from "ethers";

const ecInstance = new ec("secp256k1");
const Ciphersuite = {
    ID: 'FROST_secp256k1_SHA256',
    CONTEXT: 'FROST_secp256k1_SHA256_CONTEXT',
    q: ecInstance.curve.n,
    G: ecInstance.g,
};

type Point = ec.KeyPair;

type Participant = {
    id: BN;
    coefficients: BN[];
    proofOfKnowledge: [Point, BN];
    publicKey: Point;
    secretShare?: BN;
    nonce?: [BN, BN];
    signatureShare?: BN;
};

function randomBytes(bytesLength = 32) {
    const random = new Uint8Array(bytesLength);
    if (typeof process === 'object' && typeof require === 'function') {
        return require('crypto').randomBytes(bytesLength);
    }
    return crypto.getRandomValues(random);
}

const getRandomNumber = () => new BN(randomBytes()).mod(new BN(Ciphersuite.q));

export function createParticipant(id: BN, t: number): Participant {
    const coefficients = Array.from({ length: t }, () => getRandomNumber());
    const secret = coefficients[0];
    const proofOfKnowledge = schnorrProve(secret);
    const publicKey = ecInstance.keyFromPrivate(secret);
    return {
        id,
        coefficients,
        proofOfKnowledge,
        publicKey,
    };
}

function schnorrProve(secret: BN): [Point, BN] {
    const r = getRandomNumber();
    const R = ecInstance.keyFromPrivate(r);
    const P = ecInstance.keyFromPrivate(secret);
    const c = challenge(P, R);
    const s = r.add(secret.mul(c)).umod(new BN(Ciphersuite.q));
    return [R, s];
}

function challenge(P: Point, R: Point, message?: Uint8Array): BN {
    const P_x = P.getPublic().getX();
    const P_y = P.getPublic().getY();
    const R_x = R.getPublic().getX();
    const R_y = R.getPublic().getY();

    let hash_input = [
        { type: 'uint256', value: '0x' + R_x.toString(16) },
        { type: 'uint256', value: '0x' + R_y.toString(16) },
        { type: 'uint256', value: '0x' + P_x.toString(16) },
        { type: 'uint256', value: '0x' + P_y.toString(16) },
    ];

    if (message) {
        hash_input.push({ type: 'bytes', value: message });
    }

    const msg = ethers.solidityPackedKeccak256(
        hash_input.map(i => i.type),
        hash_input.map(i => i.value)
    );

    return new BN(msg.slice(2), 16).umod(new BN(Ciphersuite.q));
}

export function calculateSecretShare(coefficients: BN[], id: BN): BN {
    let share = new BN(0);
    for (let i = 0; i < coefficients.length; i++) {
        share = share.add(coefficients[i].mul(id.pow(new BN(i)))).umod(new BN(Ciphersuite.q));
    }
    return share;
}

export function aggregatePublicKeys(publicKeys: Point[]): Point {
    return publicKeys.reduce((acc: ec.KeyPair | null, pk) => {
        const point = pk.getPublic();
        return acc ? ecInstance.keyFromPublic(acc.getPublic().add(point)) : ecInstance.keyFromPublic(point);
    }, null) as Point;
}

function getBinding(participantId: BN, message: Uint8Array, commitments: [Point, Point][]): BN {
    const types = ['uint256', 'bytes'];
    const values: (string | Uint8Array)[] = [participantId.toString(), message];

    for (const [D, E] of commitments) {
        types.push('bytes32', 'bytes32');
        values.push('0x' + D.getPublic().getX().toString(16), '0x' + E.getPublic().getX().toString(16));
    }

    const hash = ethers.solidityPackedKeccak256(types, values);
    return new BN(hash.slice(2), 16).umod(new BN(Ciphersuite.q));
}

export function signRound1(participant: Participant): [Point, Point] {
    const d = getRandomNumber();
    const e = getRandomNumber();
    participant.nonce = [d, e];
    const D = ecInstance.keyFromPrivate(d);
    const E = ecInstance.keyFromPrivate(e);
    return [D, E];
}

export function signRound2(participant: Participant, message: Uint8Array, commitments: [Point, Point][], groupPublicKey: Point): BN {
    if (!participant.nonce || !participant.secretShare) {
        throw new Error('Participant has not completed round 1 or DKG');
    }
    const R = commitments.reduce((acc: ec.KeyPair | null, [c]) => {
        const point = c.getPublic();
        return acc ? ecInstance.keyFromPublic(acc.getPublic().add(point)) : ecInstance.keyFromPublic(point);
    }, null);
    if (!R) throw new Error('No commitments provided');
    const rho_i = getBinding(participant.id, message, commitments);
    const c = challenge(groupPublicKey, R, message);
    const lambda_i = lagrange(participant.id, commitments.map((_, i) => new BN(i + 1)));
    const z_i = participant.nonce[0].add(participant.nonce[1].mul(rho_i)).add(lambda_i.mul(participant.secretShare).mul(c)).umod(new BN(Ciphersuite.q));
    return z_i;
}

export function aggregateSignatures(signatureShares: BN[], commitments: [Point, Point][], groupPublicKey: Point, message: Uint8Array): { R: Point, z: BN } {
    const z = signatureShares.reduce((acc, s) => acc.add(s)).umod(new BN(Ciphersuite.q));
    const R = commitments.reduce((acc: ec.KeyPair | null, [c]) => {
        const point = c.getPublic();
        return acc ? ecInstance.keyFromPublic(acc.getPublic().add(point)) : ecInstance.keyFromPublic(point);
    }, null);
    if (!R) throw new Error('No commitments provided');
    const c = challenge(groupPublicKey, R, message);
    const Gz = ecInstance.g.mul(z);
    const RcPk = R.getPublic().add(groupPublicKey.getPublic().mul(c));
    console.log("z", z.toString(16));
    console.log("R", R.getPublic().getX().toString(16), R.getPublic().getY().toString(16));
    console.log("c", c.toString(16));
    console.log("Gz", Gz.getX().toString(16), Gz.getY().toString(16));
    console.log("RcPk", RcPk.getX().toString(16), RcPk.getY().toString(16));
    if (!Gz.eq(RcPk)) {
        throw new Error('Aggregated signature is invalid');
    }
    return { R, z };
}

function lagrange(i: BN, S: BN[]): BN {
    let num = new BN(1);
    let den = new BN(1);
    for (const j of S) {
        if (i.eq(j))
            continue;
        num = num.mul(j).umod(new BN(Ciphersuite.q));
        const j_sub_i = j.sub(i);
        let temp = den.mul(j_sub_i);
        den = temp.mod(new BN(Ciphersuite.q));
        if (den.isNeg()) {
            den = den.add(new BN(Ciphersuite.q));
        }
    }
    if (den.isZero()) {
        throw new Error("Division by zero in lagrange interpolation");
    }
    return num.mul(den.invm(new BN(Ciphersuite.q))).umod(new BN(Ciphersuite.q));
}