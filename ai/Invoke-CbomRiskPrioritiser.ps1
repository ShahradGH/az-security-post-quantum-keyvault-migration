# Invoke-CbomRiskPrioritiser.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [PSCustomObject[]]$CbomAssets,
    [Parameter()] [int]$EstimatedMigrationYears = 2,
    [Parameter()] [string]$ScoringModelPath = (Join-Path $PSScriptRoot 'cbom-hndl-scoring-model.json'),
    [Parameter()] [string]$FoundryEndpoint = '',
    [Parameter()] [string]$FoundryApiKey = '',
    [Parameter()] [scriptblock]$FoundryInvoker = $null
)

$ErrorActionPreference = 'Stop'

function Remove-CbomPromptInjection {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    return ($Text -replace '(?i)(ignore\s+previous\s+instructions|system\s*:|assistant\s*:|<\|.*?\|>)', '[REDACTED_INJECTION]').Trim()
}

if (-not (Test-Path $ScoringModelPath)) {
    throw "CBOM HNDL scoring model not found at '$ScoringModelPath'."
}
$model = Get-Content $ScoringModelPath -Raw -Encoding UTF8 | ConvertFrom-Json
$threatHorizon = [int]$model.moscaTheorem.defaultQuantumThreatHorizonYears

$scoredAssets = foreach ($asset in $CbomAssets) {
    $assetId = Remove-CbomPromptInjection -Text ([string]$asset.assetId)
    $alg = ([string]$asset.algorithm).ToUpperInvariant()
    $tls = [string]$asset.tlsVersion
    $retention = [int]$asset.retentionYears
    $publicExposed = if ($asset.PSObject.Properties['publiclyExposed']) { [bool]$asset.publiclyExposed } else { $true }

    # Mosca's Theorem: (X + Y) > Z
    $moscaSum = $EstimatedMigrationYears + $retention
    $moscaViolated = ($moscaSum -gt $threatHorizon)

    $score = 0.0
    $drivers = [System.Collections.Generic.List[string]]::new()

    if ($alg -match 'RSA-1024|RSA-2048|ECDSA-P256|ECC-256') {
        $score += [double]$model.weights.quantumVulnerableAlgorithm
        $drivers.Add("Quantum-vulnerable asymmetric algorithm ($alg)")
    } elseif ($alg -match 'RSA-3072|RSA-4096') {
        $score += ([double]$model.weights.quantumVulnerableAlgorithm * 0.5)
        $drivers.Add("Transitional classical key size ($alg)")
    }

    if ($moscaViolated) {
        $score += [double]$model.weights.longRetentionHorizon
        $drivers.Add("Mosca Theorem violated: ${EstimatedMigrationYears}y migration + ${retention}y retention > ${threatHorizon}y horizon")
    }

    if ($publicExposed) {
        $score += [double]$model.weights.publicInternetExposure
        $drivers.Add('Publicly exposed endpoint susceptible to passive HNDL capture')
    }

    if ($tls -notmatch '^1\.3') {
        $score += [double]$model.weights.legacyTlsBelow13
        $drivers.Add("Legacy TLS $tls lacks X25519MLKEM768 hybrid key exchange")
    }

    $score = [Math]::Round([Math]::Min($score, 1.0), 2)
    $abstained = ($score -gt 0 -and $retention -le 0)

    $wave = if ($abstained) {
        'ABSTAIN_VERIFY_DATA_RETENTION_TAG'
    } elseif ($score -ge 0.80) {
        'WAVE_1_IMMEDIATE_30D'
    } elseif ($score -ge 0.55) {
        'WAVE_2_Q1_90D'
    } else {
        'WAVE_3_BASELINE_180D'
    }

    [PSCustomObject]@{
        AssetId             = $assetId
        Algorithm           = $alg
        TlsVersion          = $tls
        RetentionYears      = $retention
        MoscaViolated       = $moscaViolated
        HndlRiskScore       = $score
        MigrationWave       = $wave
        Abstained           = $abstained
        RiskDrivers         = @($drivers)
    }
}

$ranked = @($scoredAssets | Sort-Object HndlRiskScore -Descending)

$aiExecutiveBrief = $null
if (-not [string]::IsNullOrWhiteSpace($FoundryEndpoint) -and (-not [string]::IsNullOrWhiteSpace($FoundryApiKey) -or $null -ne $FoundryInvoker)) {
    $wave1Count = @($ranked | Where-Object { $_.MigrationWave -eq 'WAVE_1_IMMEDIATE_30D' }).Count
    $payload = @{
        model       = 'gpt-4o-mini'
        temperature = 0.0
        messages    = @(
            @{ role = 'system'; content = 'You are a Chief Cryptographic Architect. Summarise CBOM HNDL migration priorities in British English. Distinguish Azure Key Vault / Managed HSM at-rest keys from edge TLS 1.3 X25519MLKEM768 proxies.' },
            @{ role = 'user'; content = "TotalAssets=$($ranked.Count); Wave1Immediate=$wave1Count; TopAsset=$($ranked[0].AssetId) Score=$($ranked[0].HndlRiskScore)" }
        )
    }
    if ($null -ne $FoundryInvoker) {
        $aiExecutiveBrief = & $FoundryInvoker $FoundryEndpoint $payload
    } else {
        $headers = @{ 'api-key' = $FoundryApiKey; 'Content-Type' = 'application/json' }
        $resp = Invoke-RestMethod -Method Post -Uri $FoundryEndpoint -Headers $headers -Body ($payload | ConvertTo-Json -Depth 6)
        $aiExecutiveBrief = $resp.choices[0].message.content
    }
}

return [PSCustomObject]@{
    Standard         = $model.standard
    TotalAssets      = $ranked.Count
    Wave1Count       = @($ranked | Where-Object { $_.MigrationWave -eq 'WAVE_1_IMMEDIATE_30D' }).Count
    PrioritisedPlan  = $ranked
    AiExecutiveBrief = $aiExecutiveBrief
}
