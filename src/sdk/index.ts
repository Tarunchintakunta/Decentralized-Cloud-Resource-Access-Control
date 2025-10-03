import { ethers } from "ethers";
import * as frost from "../frost";
import { AccessControlCore } from "../../typechain-types";

export class FrostSDK {
    private provider: ethers.providers.Provider;
    private accessControlCore: AccessControlCore;

    constructor(provider: ethers.providers.Provider, accessControlCoreAddress: string) {
        this.provider = provider;
        this.accessControlCore = new ethers.Contract(accessControlCoreAddress, [], this.provider) as AccessControlCore;
    }

    async requestAuthorization(
        participants: any[],
        message: string,
        merkleProof: string[],
        leaf: string
    ): Promise<boolean> {
        const messageHash = ethers.utils.sha256(ethers.utils.toUtf8Bytes(message));
        const groupPublicKey = frost.aggregatePublicKeys(participants.map((p) => p.publicKey));

        const signingParticipants = participants.slice(0, 2); // Assuming t = 2
        const commitments = signingParticipants.map((p) => frost.signRound1(p));
        const signatureShares = signingParticipants.map((p) =>
            frost.signRound2(p, new TextEncoder().encode(message), commitments, groupPublicKey)
        );

        const { R, z } = frost.aggregateSignatures(
            signatureShares,
            commitments,
            groupPublicKey,
            new TextEncoder().encode(message)
        );

        return this.accessControlCore.checkAccess(
            messageHash,
            R.toAffine().x,
            z,
            { x: groupPublicKey.toAffine().x, y: groupPublicKey.toAffine().y },
            merkleProof,
            leaf
        );
    }
}

// Example Usage
async function main() {
    const provider = new ethers.providers.JsonRpcProvider("http://localhost:8545");
    const accessControlCoreAddress = "0x..."; // Replace with deployed address
    const sdk = new FrostSDK(provider, accessControlCoreAddress);

    const participants = Array.from({ length: 3 }, (_, i) => frost.createParticipant(BigInt(i + 1), 2));
    const message = "hello world";
    const leaf = ethers.utils.sha256(ethers.utils.toUtf8Bytes("policy"));
    const merkleTree = ["0x..."]; // Replace with actual merkle proof
    const merkleProof = merkleTree;

    const authorized = await sdk.requestAuthorization(participants, message, merkleProof, leaf);
    console.log("Authorized:", authorized);

    // Mock AWS/Azure integration
    if (authorized) {
        console.log("Granting access to AWS/Azure resource...");
    }
}

main().catch(console.error);
