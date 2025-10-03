# Slither Scan Report

## Summary

- **Contracts Analyzed:** 13
- **Detectors Run:** 100
- **Results Found:** 23

## High Severity Issues

None

## Medium Severity Issues

None

## Low Severity Issues

None

## Informational Issues

- **Uninitialized State Variables:** `AccessControlCore.circuitBreaker` is never initialized.
- **Local Variable Shadowing:** `EllipticCurve.add().p` and `EllipticCurve.mul().p` shadow the `EllipticCurve.p()` function.
- **Assembly Usage:** Assembly is used in OpenZeppelin's `AccessControlUpgradeable`, `Initializable`, and `Hashes` contracts.
- **Different Pragma Directives:** 4 different versions of Solidity are used.
- **Incorrect Versions of Solidity:** Several version constraints contain known severe issues.
- **Naming Conventions:** Several functions and parameters do not follow the `mixedCase` or `UPPER_CASE_WITH_UNDERSCORES` naming conventions.
- **State Variables That Could Be Declared Constant:** `AccessControlCore.circuitBreaker` and `AccessControlCore.policyMerkleRoot` could be declared constant.
- **State Variables That Could Be Declared Immutable:** `PolicyManager.accessControlCore` could be declared immutable.
