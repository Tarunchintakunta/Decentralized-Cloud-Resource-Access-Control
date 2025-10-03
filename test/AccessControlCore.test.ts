import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { AccessControlCore } from "../typechain-types";

describe("AccessControlCore", function () {
    let accessControlCore: AccessControlCore;

    beforeEach(async function () {
        const FROSTVerifier = await ethers.getContractFactory("FROSTVerifier");
        const frostVerifier = await FROSTVerifier.deploy();
        await frostVerifier.waitForDeployment();

        const PolicyManager = await ethers.getContractFactory("PolicyManager");
        const policyManager = await PolicyManager.deploy("0x0000000000000000000000000000000000000000");
        await policyManager.waitForDeployment();

        const AccessControlCore = await ethers.getContractFactory("AccessControlCore");
        accessControlCore = (await upgrades.deployProxy(AccessControlCore, [await frostVerifier.getAddress(), await policyManager.getAddress()], { initializer: 'initialize' })) as AccessControlCore;
        await accessControlCore.waitForDeployment();
    });

    it("Should be upgradeable", async function () {
        const AccessControlCoreV2 = await ethers.getContractFactory("AccessControlCore");
        const upgraded = await upgrades.upgradeProxy(await accessControlCore.getAddress(), AccessControlCoreV2);
        expect(await upgraded.getAddress()).to.equal(await accessControlCore.getAddress());
    });
});
