# Test-KeyVaultPostQuantumReadiness.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [PSCustomObject]$KeyMetadata,
    [Parameter(Mandatory)] [PSCustomObject]$EndpointTlsConfig
)

$ErrorActionPreference = 'Stop'
$findings = [System.Collections.Generic.List[string]]::new()

# 1. Veto RSA keys < 3072 bits on data tiers with >5-year retention
if ($KeyMetadata.KeyType -in @('RSA', 'RSA-HSM') -and $KeyMetadata.KeySize -lt 3072) {
    $findings.Add("WEAK_ASYMMETRIC_KEY_SIZE: Key '$($KeyMetadata.KeyName)' uses $($KeyMetadata.KeyType)-$($KeyMetadata.KeySize) (Minimum required: 3072/4096 HSM).")
}

# 2. Veto missing automated Key Vault rotation policy (> 90 days)
if (-not $KeyMetadata.HasAutoRotationPolicy -or $KeyMetadata.RotationIntervalDays -gt 90) {
    $findings.Add("MISSING_OR_SLOW_ROTATION: Key '$($KeyMetadata.KeyName)' lacks <=90-day automated rotation policy.")
}

# 3. Veto legacy TLS 1.0/1.1/1.2 on long-horizon data transit endpoints
if ($EndpointTlsConfig.DataRetentionYears -ge 10 -and (-not $EndpointTlsConfig.Tls13Enabled -or -not $EndpointTlsConfig.HybridMlKem768Enabled)) {
    $findings.Add("HNDL_TRANSIT_EXPOSURE: Endpoint '$($EndpointTlsConfig.EndpointName)' holds >=10yr data without TLS 1.3 + X25519MLKEM768.")
}

return [PSCustomObject]@{
    VaultName      = $KeyMetadata.VaultName
    KeyName        = $KeyMetadata.KeyName
    Compliant      = ($findings.Count -eq 0)
    Verdict        = if ($findings.Count -eq 0) { 'COMPLIANT_PQC_HYBRID_READY' } else { 'VETO_CRYPTOGRAPHIC_DRIFT' }
    Findings       = @($findings)
}
