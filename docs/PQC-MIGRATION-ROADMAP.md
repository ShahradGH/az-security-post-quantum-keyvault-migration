# Post-Quantum Cryptography Migration Roadmap & Operational Runbook

## 1. Architectural Separation: Transit Hybrid PQC vs At-Rest Key Vault

A credible Post-Quantum Cryptography (PQC) migration roadmap must clearly distinguish **what is protected in transit today** from **how at-rest Key Management Services (KMS) are hardened**:

1. **Transit Layer (Edge TLS 1.3 Proxies & SymCrypt)**: Harvest-Now-Decrypt-Later (HNDL) adversaries capture encrypted internet traffic today to decrypt once fault-tolerant quantum computers mature. Defeating HNDL requires enabling **TLS 1.3 with hybrid `X25519MLKEM768` (NIST FIPS 203)** at edge TLS proxies and Windows/Linux endpoints using SymCrypt.
2. **At-Rest Layer (Azure Key Vault & Managed HSM)**: Native Azure Key Vault and Managed HSM keys (`RSA-HSM`, `EC-HSM`) remain classical today. Rather than making unsupported claims about native ML-KEM inside Key Vault, this framework hardens Key Vault via:
   - Minimum `3072-bit` / `4096-bit` RSA-HSM keys (`policies/audit-legacy-rsa-key-sizes.json`)
   - Automated `P90D` key rotation policies via Key Vault REST `api-version=7.5` (`src/Invoke-KeyVaultPqcRotation.ps1`)
   - Crypto-agile envelope encryption readiness

## 2. Three-Wave CBOM Migration Schedule (Mosca's Theorem)

`ai/Invoke-CbomRiskPrioritiser.ps1` evaluates CycloneDX CBOM 1.6 inventories using Mosca's Theorem (`MigrationTimeYears + DataRetentionYears > QuantumThreatHorizonYears`):

- **Wave 1 (`WAVE_1_IMMEDIATE_30D`, Score >= 0.80)**: Publicly exposed endpoints carrying `>= 10-year` retention data on TLS 1.2 or RSA-2048. Deploy Edge TLS 1.3 `X25519MLKEM768` proxy and rotate Key Vault keys to `RSA-HSM-4096` with `P90D` `rotationPolicy`.
- **Wave 2 (`WAVE_2_Q1_90D`, Score >= 0.55)**: Internal or medium-retention workloads. Enforce `P90D` automated rotation and run `src/Test-TlsMtuFragmentation.ps1` against Path MTU `1500`.
- **Wave 3 (`WAVE_3_BASELINE_180D`, Score < 0.55)**: Ephemeral or short-retention workloads. Maintain CBOM telemetry via `queries/KeyVault-Cipher-Audit.kql`.

## 3. L2/L3 Troubleshooting: PMTU Blackholes with Hybrid Key Shares

Adding `ML-KEM-768` increases the TLS 1.3 `ClientHello` KeyShare extension to ~`1,216 bytes` (total `ClientHello` ~`1,441 bytes`). On standard `1500-byte` Ethernet (`MSS = 1460 bytes`), this fits in a single TCP segment. However, GRE/IPsec/VXLAN overlays with `MTU < 1480 bytes` fragment the `ClientHello`, causing silent handshake timeouts on misconfigured firewalls. Always run `src/Test-TlsMtuFragmentation.ps1` before enabling `X25519MLKEM768` in production.
