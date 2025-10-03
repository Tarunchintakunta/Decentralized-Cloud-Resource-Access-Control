import { ethers } from "hardhat";
import { AccessControlCore } from "../typechain-types";

async function main() {
    const accessControlCoreAddress = "0x..."; // Replace with deployed address
    const accessControlCore = await ethers.getContractAt("AccessControlCore", accessControlCoreAddress);

    const transactions = 100;
    let successfulTransactions = 0;
    const startTime = Date.now();

    for (let i = 0; i < transactions; i++) {
        try {
            const message = ethers.utils.sha256(ethers.utils.toUtf8Bytes(`hello world ${i}`));
            const signatureR = "0x..."; // Replace with actual signature
            const signatureZ = "0x..."; // Replace with actual signature
            const groupPublicKey = { x: "0x...", y: "0x..." }; // Replace with actual public key
            const merkleProof: string[] = []; // Replace with actual merkle proof
            const leaf = ethers.utils.sha256(ethers.utils.toUtf8Bytes("policy"));

            const tx = await accessControlCore.checkAccess(
                message,
                signatureR,
                signatureZ,
                groupPublicKey,
                merkleProof,
                leaf
            );
            await tx.wait();
            successfulTransactions++;
        } catch (error) {
            console.error("Transaction failed:", error);
        }
    }

    const endTime = Date.now();
    const duration = (endTime - startTime) / 1000;
    const tps = successfulTransactions / duration;

    console.log(`Total transactions: ${transactions}`);
    console.log(`Successful transactions: ${successfulTransactions}`);
    console.log(`Duration: ${duration}s`);
    console.log(`TPS: ${tps}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
