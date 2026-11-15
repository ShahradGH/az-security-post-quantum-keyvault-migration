# Send-CisoCbomBriefing.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [PSCustomObject]$PrioritisationPlan,
    [Parameter(Mandatory)] [string]$TeamId,
    [Parameter(Mandatory)] [string]$ChannelId,
    [Parameter()] [string]$ComplianceSiteId = '',
    [Parameter()] [string]$ComplianceListId = '',
    [Parameter()] [scriptblock]$GraphInvoker = $null
)

$ErrorActionPreference = 'Stop'

function Invoke-GraphCisoApi {
    param([string]$Method, [string]$Uri, [hashtable]$Body)
    if ($null -ne $GraphInvoker) {
        return & $GraphInvoker $Method $Uri $Body
    }
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 12) -ContentType 'application/json'
}

$topWave1 = @($PrioritisationPlan.PrioritisedPlan | Where-Object { $_.MigrationWave -eq 'WAVE_1_IMMEDIATE_30D' } | Select-Object -First 3)
$topSummary = if ($topWave1.Count -gt 0) {
    ($topWave1 | ForEach-Object { "- $($_.AssetId) (Score: $($_.HndlRiskScore), Retention: $($_.RetentionYears)y)" }) -join "`n"
} else {
    '- Zero Wave 1 immediate HNDL exposures detected.'
}

$card = @{
    type    = 'AdaptiveCard'
    version = '1.5'
    body    = @(
        @{
            type   = 'TextBlock'
            text   = "CISO Post-Quantum CBOM Briefing ($($PrioritisationPlan.Standard))"
            weight = 'Bolder'
            size   = 'Medium'
            color  = if ($PrioritisationPlan.Wave1Count -gt 0) { 'Attention' } else { 'Good' }
        },
        @{
            type  = 'FactSet'
            facts = @(
                @{ title = 'Total Assets Audited'; value = [string]$PrioritisationPlan.TotalAssets },
                @{ title = 'Wave 1 (30-Day Immediate)'; value = [string]$PrioritisationPlan.Wave1Count }
            )
        },
        @{
            type = 'TextBlock'
            text = "Top HNDL Priorities:`n$topSummary"
            wrap = $true
        }
    )
}

$attId = [guid]::NewGuid().ToString()
$teamsUri = "https://graph.microsoft.com/v1.0/teams/$TeamId/channels/$ChannelId/messages"
$teamsResp = Invoke-GraphCisoApi -Method 'POST' -Uri $teamsUri -Body @{
    body        = @{ contentType = 'html'; content = "<attachment id=`"$attId`"></attachment>" }
    attachments = @(@{ id = $attId; contentType = 'application/vnd.microsoft.card.adaptive'; content = ($card | ConvertTo-Json -Depth 10 -Compress) })
}

$spLogged = $false
if (-not [string]::IsNullOrWhiteSpace($ComplianceSiteId) -and -not [string]::IsNullOrWhiteSpace($ComplianceListId)) {
    $listUri = "https://graph.microsoft.com/v1.0/sites/$ComplianceSiteId/lists/$ComplianceListId/items"
    $null = Invoke-GraphCisoApi -Method 'POST' -Uri $listUri -Body @{
        fields = @{
            Title       = "CBOM Briefing - Wave 1 Count: $($PrioritisationPlan.Wave1Count)"
            TotalAssets = [int]$PrioritisationPlan.TotalAssets
            Standard    = [string]$PrioritisationPlan.Standard
        }
    }
    $spLogged = $true
}

return [PSCustomObject]@{
    BriefingSent     = $true
    TeamsEndpoint    = $teamsUri
    TeamsMessageId   = $teamsResp.id
    SharePointLogged = $spLogged
    Wave1Count       = $PrioritisationPlan.Wave1Count
}
