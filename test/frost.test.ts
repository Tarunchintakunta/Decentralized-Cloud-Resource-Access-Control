import { expect } from "chai";
import { ethers } from "hardhat";
import * as frost from "../src/frost/index";
import { secp256k1 } from "@noble/curves/secp256k1.js";

describe("FROST Protocol", function () {
    it("Should complete a DKG and signing ceremony", async function () {
        const n = 3;
        const t = 2;
        const message = new TextEncoder().encode("hello world");

        // DKG
        const participants = Array.from({ length: n }, (_, i) => frost.createParticipant(BigInt(i + 1), t));
        const secretShares = participants.map((p) =>
            participants.map((receiver) => frost.calculateSecretShare(p.coefficients, receiver.id))
        );

        for (let i = 0; i < n; i++) {
            participants[i].secretShare = secretShares.reduce((acc, share) => acc + share[i], 0n);
        }

        const groupPublicKey = frost.aggregatePublicKeys(participants.map((p) => p.publicKey));

        // Signing
        const signingParticipants = participants.slice(0, t);
        const commitments = signingParticipants.map((p) => frost.signRound1(p));

        const signatureShares = signingParticipants.map((p) =>
            frost.signRound2(p, message, commitments, groupPublicKey)
        );

        const { R, z } = frost.aggregateSignatures(
            signatureShares,
            commitments,
            groupPublicKey,
            message
        );

        const Gz = secp256k1.ProjectivePoint.BASE.multiply(z);
        const c = BigInt(`0x${Buffer.from(ethers.utils.sha256(new TextEncoder().encode("frost"))).toString('hex')}`);
        const RcPk = R.add(groupPublicKey.multiply(c));

        // Final verification is inside aggregateSignatures, but we can double check
        expect(Gz.equals(RcPk)).to.be.true;
    });
});
