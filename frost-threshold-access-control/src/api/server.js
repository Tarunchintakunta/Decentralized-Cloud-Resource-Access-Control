const express = require('express');
const { ethers } = require('ethers');
const AWS = require('aws-sdk');
const { DefaultAzureCredential } = require('@azure/identity');
const { ResourceManagementClient } = require('@azure/arm-resources');
const FROST = require('../crypto/frost');

// Load contract ABI (would be generated from compilation)
const contractABI = require('../../build/contracts/FROSTAccessControl.json').abi;

const app = express();
app.use(express.json());

// Configure blockchain connection
const provider = new ethers.providers.JsonRpcProvider('http://localhost:8545'); // For local testing
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider); // Replace with actual private key management
const contractAddress = 'YOUR_CONTRACT_ADDRESS'; // Will be set after deployment
const contract = new ethers.Contract(contractAddress, contractABI, wallet);

// Configure AWS
const iam = new AWS.IAM({
  region: 'us-east-1',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

// Configure Azure
const azureCredential = new DefaultAzureCredential();
const resourceClient = new ResourceManagementClient(azureCredential, process.env.AZURE_SUBSCRIPTION_ID);

// Initialize FROST
const frost = new FROST(2, 3); // t-of-n threshold scheme

// Routes
app.post('/api/request-access', async (req, res) => {
  try {
    const { resourceId, requester, validUntil } = req.body;
    
    // Generate message hash
    const messageHash = ethers.utils.solidityKeccak256(
      ['string', 'bytes32', 'address', 'uint32'],
      ['ACCESS_REQUEST', resourceId, requester, validUntil]
    );
    
    // Get signers to participate in threshold signing
    // In a real application, this would involve a distributed signing process
    const signerIndices = [1, 2]; // Example: signers 1 and 2 participate
    
    // Generate FROST signature
    // In a real app, this would be distributed across multiple parties
    await frost.generateShares(); // This would be a one-time setup in reality
    const commitment1 = await frost.generateCommitment(1);
    const commitment2 = await frost.generateCommitment(2);
    const signature = await frost.signMessage(messageHash, signerIndices);
    
    // Convert signature to format expected by the contract
    const { r, s } = signature;
    const v = 27; // Example recovery value, would be calculated properly in production
    
    // Submit transaction to the blockchain
    const tx = await contract.requestAccess(
      resourceId,
      requester,
      validUntil,
      ethers.utils.hexlify(Buffer.from(r + s, 'hex')),
      messageHash,
      v
    );
    
    const receipt = await tx.wait();
    
    // Update cloud provider permissions
    // This is highly simplified - in a real implementation, this would involve
    // more complex permission management
    
    if (req.body.cloudProvider === 'aws') {
      // AWS IAM policy update
      const params = {
        PolicyArn: req.body.policyArn,
        UserName: req.body.username
      };
      await iam.attachUserPolicy(params).promise();
    } 
    else if (req.body.cloudProvider === 'azure') {
      // Azure RBAC update
      await resourceClient.roleAssignments.create(
        req.body.scope,
        req.body.roleAssignmentId,
        {
          roleDefinitionId: req.body.roleDefinitionId,
          principalId: req.body.principalId
        }
      );
    }
    
    res.status(200).json({ 
      success: true, 
      transactionHash: receipt.transactionHash,
      accessGranted: true
    });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/check-access', async (req, res) => {
  try {
    const { resourceId, requester } = req.query;
    
    // Check access on the blockchain
    const hasAccess = await contract.hasAccess(resourceId, requester);
    
    res.status(200).json({ hasAccess });
  } catch (error) {
    console.error('Error checking access:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});

module.exports = app;