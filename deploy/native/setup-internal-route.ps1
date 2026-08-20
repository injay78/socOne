<#
.SYNOPSIS
    Route internal traffic over the corporate NIC while the internet keeps using Wi-Fi.

.DESCRIPTION
    This host is multi-homed: a corporate Ethernet link reaches internal systems,
    and a guest Wi-Fi link reaches the internet. Wi-Fi wins the default route, so
    without an explicit route every internal address that is not on the Ethernet
    subnet is sent to Wi-Fi and times out.

    Adding a persistent route for RFC1918 10.0.0.0/8 sends internal traffic over
    Ethernet and leaves everything else on the default route. Internet traffic
    then avoids the corporate TLS inspection proxy.

    Must be run from an elevated PowerShell. Re-running it is safe.

.EXAMPLE
    .\setup-internal-route.ps1
    .\setup-internal-route.ps1 -InterfaceAlias Ethernet0 -NextHop 10.8.4.1 -Prefix 10.0.0.0/8
#>
param(
    [string]$InterfaceAlias = "Ethernet0",
    [string]$NextHop        = "10.8.4.1",
    [string]$Prefix         = "10.0.0.0/8",
    [string]$VerifyTarget   = "10.4.27.7",
    [int]   $VerifyPort     = 443,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

function Log-Info  { param($m) Write-Host "[INFO]  $m" -ForegroundColor Green  }
function Log-Warn  { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Log-Error { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red    }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Log-Error "This script changes the routing table and must run from an elevated PowerShell."
    exit 1
}

$adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue
if (-not $adapter) { Log-Error "Adapter '$InterfaceAlias' not found."; exit 1 }
if ($adapter.Status -ne "Up") { Log-Warn "Adapter '$InterfaceAlias' is $($adapter.Status)." }

# route.exe is used instead of New-NetRoute because New-NetRoute rejects
# -PolicyStore PersistentStore with Windows System Error 87 on this platform.
# "route -p add" writes to the active table and the persistent store at once.
$parts   = $Prefix.Split('/')
$network = $parts[0]
$bits    = [int]$parts[1]
$binary  = ('1' * $bits).PadRight(32, '0')
$mask    = (0..3 | ForEach-Object { [Convert]::ToInt32($binary.Substring($_ * 8, 8), 2) }) -join '.'

if ($Remove) {
    & route.exe delete $network mask $mask | Out-Null
    Log-Info "Removed $Prefix ($network mask $mask)."
    exit 0
}

$existing = Get-NetRoute -DestinationPrefix $Prefix -InterfaceAlias $InterfaceAlias -ErrorAction SilentlyContinue
if ($existing) {
    Log-Info "Route $Prefix via $InterfaceAlias already present."
} else {
    $output = & route.exe -p add $network mask $mask $NextHop metric 1 if $($adapter.ifIndex)
    if ($LASTEXITCODE -ne 0) {
        Log-Error "route add failed: $output"
        exit 1
    }
    Log-Info "Added persistent route $network mask $mask -> $NextHop via $InterfaceAlias (ifIndex $($adapter.ifIndex))."
}

Write-Host ""
Log-Info "Default routes (lowest Effective wins):"
Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
    Select-Object InterfaceAlias, NextHop,
                  @{n='Effective';e={$_.RouteMetric + $_.InterfaceMetric}} |
    Sort-Object Effective | Format-Table -AutoSize

Log-Info "Verifying that $VerifyTarget`:$VerifyPort is reachable without binding a source address..."
$client = New-Object Net.Sockets.TcpClient
try {
    $task = $client.ConnectAsync($VerifyTarget, $VerifyPort)
    if ($task.Wait(8000) -and $client.Connected) {
        $local = $client.Client.LocalEndPoint.Address.ToString()
        Log-Info "Reachable, and the kernel chose source address $local."
        if ($local -notlike "10.*") { Log-Warn "Source address is not on the internal network - check the route." }
    } else {
        Log-Error "Still unreachable. Confirm that $NextHop is the correct internal gateway."
    }
} catch {
    Log-Error "Verification failed: $($_.Exception.Message)"
} finally {
    $client.Close()
}
