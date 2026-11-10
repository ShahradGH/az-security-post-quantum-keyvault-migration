# Quantum Readiness: Post-Quantum Cryptography (PQC) & TLS 1.3 Key Vault Migration

[![Pester Verification](https://img.shields.io/badge/pester-16%2F16%20passing-brightgreen)](tests/PostQuantumMigration.Tests.ps1)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture Deep-Dive](https://img.shields.io/badge/blog-alerasoul.net-0a1128)](https://alerasoul.net/post-quantum-cryptography-keyvault-migration/)

> **Primary Governance Artefact:** PQC Migration Assessment Tool & Key Rotation Verification Matrix  
> **Accountable Service Owner:** Chief Cryptographic Security Architect & Sovereign Security Officer  
> **Full Architectural Deep-Dive:** [https://alerasoul.net/post-quantum-cryptography-keyvault-migration/](https://alerasoul.net/post-quantum-cryptography-keyvault-migration/)

---

## Repository Layout (14 Files)

```text
├── .github/workflows/cbom-audit.yml
├── LICENSE
├── README.md
├── SECURITY.md
├── docs/PQC-MIGRATION-ROADMAP.md
├── fixtures/estate-crypto-inventory.json
├── infra/managed-hsm-pqc.bicep
├── policies/audit-legacy-rsa-key-sizes.json
├── policies/enforce-tls13-minimum.json
├── queries/KeyVault-Cipher-Audit.kql
├── schemas/cyclonedx-cbom.schema.json
├── src/Invoke-KeyVaultPqcRotation.ps1
├── src/Test-KeyVaultPostQuantumReadiness.ps1
└── tests/PostQuantumMigration.Tests.ps1
```

## Quickstart & Offline Verification

```powershell
# 1. Execute the primary PowerShell 7 evaluator
pwsh -NoProfile -File ./src/Test-KeyVaultPostQuantumReadiness.ps1

# 2. Run the 16-test Pester verification contract
Invoke-Pester -Path ./tests/PostQuantumMigration.Tests.ps1 -Output Detailed
```

## License

Released under the [MIT License](LICENSE). Authored by **Shahrad Alerasoul** ([alerasoul.net](https://alerasoul.net)).
