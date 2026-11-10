# Operational Runbook: Quantum Readiness: Post-Quantum Cryptography (PQC) & TLS 1.3 Key Vault Migration (L2 / L3 Triage)

## 1. Scope & Ownership
- **Accountable Owner**: Chief Cryptographic Security Architect & Sovereign Security Officer
- **Primary Evaluator**: `src/Test-KeyVaultPostQuantumReadiness.ps1`
- **Telemetry Source**: `diagnostics/Telemetry-Queries.kql`

## 2. Triage Procedure When Veto Gate Trips
1. Inspect the structured refusal object emitted by `src/Test-KeyVaultPostQuantumReadiness.ps1` and correlate the timestamp in Azure Monitor Log Analytics.
2. Do not bypass or disable the pre-flight policy gate without cryptographic dual-signature approval from the Chief Cryptographic Security Architect & Sovereign Security Officer.
3. Verify remediation locally by running `Invoke-Pester -Path ./tests/Boundary-Verification.Tests.ps1 -Output Detailed`.
