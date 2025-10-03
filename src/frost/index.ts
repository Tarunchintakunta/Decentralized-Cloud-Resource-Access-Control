import { ec } from "elliptic";
import BN from "bn.js";
import keccak256 from "keccak256";

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
    const R_x = R.getPublic().getX().toBuffer('be', 32);
    const R_y = R.getPublic().getY().toBuffer('be', 32);
    const P_x = P.getPublic().getX().toBuffer('be', 32);
    const P_y = P.getPublic().getY().toBuffer('be', 32);

    let hash_input = [R_x, R_y, P_x, P_y];

    if (message) {
        hash_input.push(Buffer.from(message));
    }

    const msg = keccak256(Buffer.concat(hash_input));

    return new BN(msg).umod(new BN(Ciphersuite.q));
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
    const id_bytes = participantId.toBuffer('be', 32);
    const msg_bytes = Buffer.from(message);
    const commitments_bytes = Buffer.concat(
        commitments.map(([D, E]) =>
            Buffer.concat([
                D.getPublic().getX().toBuffer('be', 32),
                D.getPublic().getY().toBuffer('be', 32),
                E.getPublic().getX().toBuffer('be', 32),
                E.getPublic().getY().toBuffer('be', 32),
            ])
        )
    );
    const hash = keccak256(Buffer.concat([id_bytes, msg_bytes, commitments_bytes]));
    return new BN(hash).umod(new BN(Ciphersuite.q));
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
