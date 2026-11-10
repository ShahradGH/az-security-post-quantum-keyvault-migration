# ADR-001: Quantum Readiness: Post-Quantum Cryptography (PQC) & TLS 1.3 Key Vault Migration

## Status
Accepted

## Service Owner & Sign-Off Authority
Chief Cryptographic Security Architect & Sovereign Security Officer

## Dominant Artefact
PQC Migration Assessment Tool & Key Rotation Verification Matrix

## Decision & Refusal Boundary
All production state mutations must pass deterministic pre-flight policy evaluation in `src/Test-KeyVaultPostQuantumReadiness.ps1` and satisfy the 16-test Pester verification contract in `tests/Boundary-Verification.Tests.ps1` before execution.
