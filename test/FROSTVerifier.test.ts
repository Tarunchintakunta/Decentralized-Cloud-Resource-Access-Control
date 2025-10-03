import { expect } from "chai";
import { ethers } from "hardhat";
import * as frost from "../src/frost/index";
import { FROSTVerifier } from "../typechain-types";
import BN from "bn.js";

describe("FROSTVerifier", function () {
    let frostVerifier: FROSTVerifier;

    before(async () => {
        const FROSTVerifier = await ethers.getContractFactory("FROSTVerifier");
        frostVerifier = await FROSTVerifier.deploy();
        await frostVerifier.waitForDeployment();
    });

    it("Should verify a valid FROST signature", async function () {
        const n = 3;
        const t = 2;
        const message = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("hello world"));

        // DKG
        const participants = Array.from({ length: n }, (_, i) => frost.createParticipant(new BN(i + 1), t));
        for (let i = 0; i < n; i++) {
            participants[i].secretShare = new BN(0);
            for (let j = 0; j < n; j++) {
                const share = frost.calculateSecretShare(participants[j].coefficients, participants[i].id);
                participants[i].secretShare = participants[i].secretShare.add(share);
            }
        }

        const groupPublicKey = frost.aggregatePublicKeys(participants.map((p) => p.publicKey));

        // Signing
        const signingParticipants = participants.slice(0, t);
        const commitments = signingParticipants.map((p) => frost.signRound1(p));

        const signatureShares = signingParticipants.map((p) => {
            return frost.signRound2(p, ethers.utils.arrayify(message), commitments, groupPublicKey)
        });

        const { R, z } = frost.aggregateSignatures(
            signatureShares,
            commitments,
            groupPublicKey,
            ethers.utils.arrayify(message)
        );

        const isValid = await frostVerifier.verify(
            message,
            R.getPublic().getX(),
            z,
            { x: groupPublicKey.getPublic().getX(), y: groupPublicKey.getPublic().getY() }
        );

        expect(isValid).to.be.true;
    });
});
