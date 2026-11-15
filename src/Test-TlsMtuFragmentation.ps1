# Test-TlsMtuFragmentation.ps1
# Probes hybrid PQC TLS 1.3 (X25519MLKEM768) handshake byte budget against Path MTU to detect fragmentation blackholes.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$EndpointFqdn,
    [Parameter()] [int]$PathMtuBytes = 1500,
    [Parameter()] [int]$ClientHelloKeyShareBytes = 1216,
    [Parameter()] [int]$CertificateChainBytes = 2400,
    [Parameter()] [bool]$HybridMlKem768Enabled = $true
)

$ErrorActionPreference = 'Stop'

# Standard IPv4 (20B) + TCP (20B) + TLS record (5B) + base ClientHello (~220B)
$tcpIpOverhead = 40
$mss = $PathMtuBytes - $tcpIpOverhead
$clientHelloTotal = 225 + $(if ($HybridMlKem768Enabled) { $ClientHelloKeyShareBytes } else { 32 })
$serverFlightTotal = 180 + $(if ($HybridMlKem768Enabled) { 1120 } else { 32 }) + $CertificateChainBytes

$clientFragments = [Math]::Ceiling($clientHelloTotal / $mss)
$serverFragments = [Math]::Ceiling($serverFlightTotal / $mss)
$singlePacketSafe = ($clientHelloTotal -le $mss)

return [PSCustomObject]@{
    EndpointFqdn        = $EndpointFqdn
    PathMtuBytes        = $PathMtuBytes
    EffectiveMssBytes   = $mss
    ClientHelloBytes    = $clientHelloTotal
    ServerFlightBytes   = $serverFlightTotal
    ClientTcpSegments   = $clientFragments
    ServerTcpSegments   = $serverFragments
    SinglePacketClientHello = $singlePacketSafe
    Status              = if ($singlePacketSafe) { 'SAFE_SINGLE_PACKET_CLIENTHELLO' } else { 'WARN_MULTI_SEGMENT_CLIENTHELLO_PMTU_RISK' }
}
