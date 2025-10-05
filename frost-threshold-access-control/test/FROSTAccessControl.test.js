const FROSTAccessControl = artifacts.require("FROSTAccessControl");
const { expectRevert, time } = require('@openzeppelin/test-helpers');
const { web3 } = require('@openzeppelin/test-helpers/src/setup');

contract("FROSTAccessControl", accounts => {
  const admin = accounts[0];
  const signer1 = accounts[1];
  const signer2 = accounts[2];
  const signer3 = accounts[3];
  const requester = accounts[4];
  const nonAdmin = accounts[5];

  const initialThreshold = 2;
  const initialSigners = [signer1, signer2, signer3];
  const dummyGroupPubKey = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  
  let accessControl;
  let resourceId;

  beforeEach(async () => {
    accessControl = await FROSTAccessControl.new(
      admin,
      initialThreshold,
      initialSigners,
      dummyGroupPubKey
    );
    
    // Create a random resource ID for each test
    resourceId = web3.utils.keccak256("Resource" + Math.random());
  });

  describe("Deployment", () => {
    it("should set the correct admin", async () => {
      const adminRole = await accessControl.ADMIN_ROLE();
      assert.equal(await accessControl.hasRole(adminRole, admin), true);
    });

    it("should add initial signers correctly", async () => {
      const signerRole = await accessControl.SIGNER_ROLE();
      
      for (const signer of initialSigners) {
        assert.equal(await accessControl.hasRole(signerRole, signer), true);
      }
    });

    it("should set the correct threshold", async () => {
      const config = await accessControl.config();
      assert.equal(config.threshold, initialThreshold);
      assert.equal(config.totalSigners, initialSigners.length);
    });
  });

  describe("Admin functions", () => {
    it("should allow admin to update threshold", async () => {
      const newThreshold = 3;
      await accessControl.updateThreshold(newThreshold, { from: admin });
      
      const config = await accessControl.config();
      assert.equal(config.threshold, newThreshold);
    });

    it("should not allow non-admin to update threshold", async () => {
      const newThreshold = 3;
      await expectRevert(
        accessControl.updateThreshold(newThreshold, { from: nonAdmin }),
        "AccessControl: account " + nonAdmin.toLowerCase() + " is missing role"
      );
    });

    it("should allow admin to add a new signer", async () => {
      const newSigner = accounts[6];
      const signerRole = await accessControl.SIGNER_ROLE();
      
      await accessControl.addSigner(newSigner, { from: admin });
      
      assert.equal(await accessControl.hasRole(signerRole, newSigner), true);
      
      const config = await accessControl.config();
      assert.equal(config.totalSigners, initialSigners.length + 1);
    });

    it("should allow admin to remove a signer", async () => {
      const signerToRemove = signer3;
      const signerRole = await accessControl.SIGNER_ROLE();
      
      await accessControl.removeSigner(signerToRemove, { from: admin });
      
      assert.equal(await accessControl.hasRole(signerRole, signerToRemove), false);
      
      const config = await accessControl.config();
      assert.equal(config.totalSigners, initialSigners.length - 1);
    });
  });

  // Note: Testing the actual FROST signature verification would require
  // more complex test setup and mock signature generation
});