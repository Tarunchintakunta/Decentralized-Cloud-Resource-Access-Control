import { ethers, upgrades } from "hardhat";

async function main() {
    const FROSTVerifier = await ethers.getContractFactory("FROSTVerifier");
    const frostVerifier = await FROSTVerifier.deploy();
    await frostVerifier.waitForDeployment();
    console.log("FROSTVerifier deployed to:", await frostVerifier.getAddress());

    const PolicyManager = await ethers.getContractFactory("PolicyManager");
    const policyManager = await PolicyManager.deploy(ethers.constants.AddressZero);
    await policyManager.waitForDeployment();
    console.log("PolicyManager deployed to:", await policyManager.getAddress());

    const AccessControlCore = await ethers.getContractFactory("AccessControlCore");
    const accessControlCore = await upgrades.deployProxy(AccessControlCore, [await frostVerifier.getAddress(), await policyManager.getAddress()], { initializer: 'initialize' });
    await accessControlCore.waitForDeployment();
    console.log("AccessControlCore deployed to:", await accessControlCore.getAddress());
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
