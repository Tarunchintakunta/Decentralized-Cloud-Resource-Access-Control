import { expect } from "chai";
import BN from "bn.js";
import * as frost from "../src/frost";

describe("FROST Protocol", function () {
    it("Should complete a DKG and signing ceremony", async function () {
        // Create participants
        const t = 2; // threshold
        const n = 3; // total participants
        const participants = Array.from({ length: n }, (_, i) => 
            frost.createParticipant(new BN(i + 1), t)
        );

        // DKG
        for (let i = 0; i < n; i++) {
            participants[i].secretShare = new BN(0);
            for (let j = 0; j < n; j++) {
                const share = frost.calculateSecretShare(participants[j].coefficients, participants[i].id);
                participants[i].secretShare = participants[i].secretShare.add(share);
            }
        }

        // Sign a message
        const message = new TextEncoder().encode("Hello, World!");
        const signingParticipants = participants.slice(0, t);

        // Round 1: Generate commitments
        const commitments = signingParticipants.map(p => frost.signRound1(p));

        // Round 2: Generate signature shares
        const groupPublicKey = frost.aggregatePublicKeys(participants.map(p => p.publicKey));
        const signatureShares = signingParticipants.map(p =>
            frost.signRound2(p, message, commitments, groupPublicKey)
        );

        // Aggregate signatures
        const signature = frost.aggregateSignatures(signatureShares, commitments, groupPublicKey, message);
        expect(signature).to.not.be.undefined;
    });
});
