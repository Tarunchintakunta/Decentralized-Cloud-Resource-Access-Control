import { expect } from "chai";
import { ethers } from "hardhat";
import * as frost from "../src/frost/index";
import { FROSTVerifier } from "../typechain-types";

describe("FROSTVerifier", function () {
    let frostVerifier: FROSTVerifier;

    before(async () => {
        await frost.initFROST();
        const FROSTVerifier = await ethers.getContractFactory("FROSTVerifier");
        frostVerifier = await FROSTVerifier.deploy();
        await frostVerifier.deployed();
    });

    it("Should verify a valid FROST signature", async function () {
        const n = 3;
        const t = 2;
        const message = ethers.utils.sha256(ethers.utils.toUtf8Bytes("hello world"));

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
            frost.signRound2(p, new TextEncoder().encode("hello world"), commitments, groupPublicKey)
        );

        const { R, z } = frost.aggregateSignatures(
            signatureShares,
            commitments,
            groupPublicKey,
            new TextEncoder().encode("hello world")
        );

        const isValid = await frostVerifier.verify(
            message,
            R.toAffine().x,
            z,
            { x: groupPublicKey.toAffine().x, y: groupPublicKey.toAffine().y }
        );

        expect(isValid).to.be.true;
    });
});
