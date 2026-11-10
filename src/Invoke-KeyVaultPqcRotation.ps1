# Invoke-KeyVaultPqcRotation.ps1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$KeyName)
Set-StrictMode -Version Latest
return [PSCustomObject]@{ VaultName = $VaultName; KeyName = $KeyName; TargetAlgorithm = 'RSA-HSM-4096-PQC-HybridReady'; RotationIntervalDays = 60 }
