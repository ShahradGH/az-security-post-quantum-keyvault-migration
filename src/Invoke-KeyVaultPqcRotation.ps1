# Invoke-KeyVaultPqcRotation.ps1
# Configures Azure Key Vault / Managed HSM key rotationPolicy (P90D) and rotates classical keys via REST.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$VaultName,
    [Parameter(Mandatory)] [string]$KeyName,
    [Parameter()] [ValidateSet('RSA-HSM', 'RSA', 'EC-HSM')] [string]$TargetKeyType = 'RSA-HSM',
    [Parameter()] [int]$TargetKeySize = 4096,
    [Parameter()] [string]$RotationIntervalIso = 'P90D',
    [Parameter()] [string]$ExpiryTimeIso = 'P1Y',
    [Parameter()] [scriptblock]$RestInvoker = $null
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($TargetKeyType -match 'RSA' -and $TargetKeySize -lt 3072) {
    throw "VETO_WEAK_KEY_SIZE: TargetKeySize $TargetKeySize is below the 3072-bit PQC transitional floor."
}

$policyUri = "https://$VaultName.vault.azure.net/keys/$KeyName/rotationpolicy?api-version=7.5"
$policyPayload = @{
    lifetimeActions = @(
        @{
            trigger = @{ timeAfterCreate = $RotationIntervalIso }
            action  = @{ type = 'Rotate' }
        },
        @{
            trigger = @{ timeBeforeExpiry = 'P30D' }
            action  = @{ type = 'Notify' }
        }
    )
    attributes = @{
        expiryTime = $ExpiryTimeIso
    }
}

$rotateUri = "https://$VaultName.vault.azure.net/keys/$KeyName/rotate?api-version=7.5"

if ($null -ne $RestInvoker) {
    $policyResp = & $RestInvoker 'PUT' $policyUri $policyPayload
    $rotateResp = & $RestInvoker 'POST' $rotateUri @{}
} else {
    $pResp = Invoke-AzRestMethod -Method PUT -Uri $policyUri -Payload ($policyPayload | ConvertTo-Json -Depth 8)
    if ($pResp.StatusCode -ge 400) { throw "Key Vault rotationPolicy PUT failed ($($pResp.StatusCode)): $($pResp.Content)" }
    $rResp = Invoke-AzRestMethod -Method POST -Uri $rotateUri -Payload '{}'
    if ($rResp.StatusCode -ge 400) { throw "Key Vault key rotate POST failed ($($rResp.StatusCode)): $($rResp.Content)" }
    $policyResp = $pResp.Content | ConvertFrom-Json
    $rotateResp = $rResp.Content | ConvertFrom-Json
}

return [PSCustomObject]@{
    VaultName           = $VaultName
    KeyName             = $KeyName
    TargetAlgorithm     = "$TargetKeyType-$TargetKeySize-PQC-Transitional"
    RotationPolicyIso   = $RotationIntervalIso
    PolicyEndpoint      = $policyUri
    RotatedKeyVersion   = $rotateResp.key.kid
    Status              = 'ROTATION_POLICY_ENFORCED_AND_ROTATED'
}
