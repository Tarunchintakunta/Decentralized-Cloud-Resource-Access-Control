# Architecture

## Overview

This document outlines the architecture of the Decentralized Cloud Resource Access Control system. The system is designed to provide a secure and decentralized way to manage access to cloud resources, using a combination of FROST threshold signatures and smart contracts on an Ethereum-based blockchain. This approach is based on the principles outlined in the thesis "Decentralized Cloud Resource Access Control using FROST + gas-optimized multi-signature smart contracts".

## Components

### 1. FROST TypeScript Library

The FROST library, located in `src/frost`, provides the core cryptographic functionality for the system. It includes:

- **Distributed Key Generation (DKG):** A set of functions for creating and distributing key shares among a group of participants. (See Thesis, Section 3.1)
- **Signing:** A two-round protocol for generating a collective Schnorr signature. (See Thesis, Section 3.2)
- **Aggregation:** Functions for aggregating public keys and signature shares. (See Thesis, Section 3.3)

### 2. Smart Contracts

The smart contracts, located in `contracts`, provide the on-chain logic for the access control system.

- **`FROSTVerifier.sol`:** A contract for verifying FROST Schnorr signatures. (See Thesis, Section 4.1)
- **`AccessControlCore.sol`:** The core contract for managing access control policies. It is upgradeable and uses a proxy pattern. (See Thesis, Section 4.2)
- **`PolicyManager.sol`:** A contract for managing Merkle-tree based permission proofs. (See Thesis, Section 4.3)

### 3. TypeScript SDK

The TypeScript SDK, located in `src/sdk`, provides a convenient way for client applications to interact with the access control system. It includes:

- **`FrostSDK`:** A class that encapsulates the logic for creating participants, generating signatures, and requesting authorization from the `AccessControlCore` contract. (See Thesis, Section 5.1)

## Flow

1. **Initialization:** A group of participants uses the FROST library to perform a DKG ceremony, generating a collective public key. (See Thesis, Section 3.1)
2. **Policy Creation:** An administrator creates an access control policy and stores its Merkle root in the `AccessControlCore` contract. (See Thesis, Section 4.3)
3. **Authorization Request:** A client application uses the TypeScript SDK to request authorization for a specific action. (See Thesis, Section 5.1)
4. **Signature Generation:** The SDK orchestrates a signing ceremony among a threshold of participants, who use their key shares to generate a collective FROST signature. (See Thesis, Section 3.2)
5. **On-Chain Verification:** The SDK submits the signature, along with a Merkle proof of the policy, to the `AccessControlCore` contract. (See Thesis, Section 4.1)
6. **Access Granted/Denied:** The `AccessControlCore` contract verifies the signature and the policy, and grants or denies access accordingly.
