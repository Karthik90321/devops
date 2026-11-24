<#
.SYNOPSIS
    Shared launcher logic for Run-DevApp-Inventory.ps1 and Run-NonProd-Inventory.ps1.
    Do not run directly - run one of the environment launchers.

.DESCRIPTION
    - Refuses to run while any <FILL-ME> placeholder is left in the launcher's settings.
    - Checks that every subscription ID is a GUID and that the signed-in account can see it.
    - Warns loudly if a subscription name looks like PRODUCTION.
    - Shows exactly what will be scanned and asks you to type the environment name to confirm
      (skipped with -ListOnly; can be skipped with -Force for unattended runs).
    - Calls Invoke-JavaInventory.ps1 with -EnvironmentLabel so each environment gets its own
      report folder:  .\JavaInventory_<Label>_<timestamp>\
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]+$')][string]$EnvironmentLabel,
    [Parameter(Mandatory)][string[]]$SubscriptionId,
    [string[]]$ResourceGroupName,
    [string[]]$VMName,
    [string[]]$ExcludeVMName,
    [string]$ExpectedCollectorSha256,
    [int]$ThrottleLimit = 10,
    [int]$ScanTimeoutMinutes = 45,
    [switch]$SkipJarScan,
    [switch]$IncludeTier0Servers,
    [switch]$ListOnly,
    [switch]$Force,
    [switch]$CleanupOnly,
    [string]$StateFile,
    [string]$OutputFolder
)
$ErrorActionPreference = 'Stop'

# 1. Placeholders / format
$check = @($SubscriptionId) + @($ResourceGroupName) + @($VMName) + @($ExcludeVMName) + @($ExpectedCollectorSha256) | Where-Object { $_ }
$unfilled = @($check | Where-Object { $_ -match '<FILL' })
if ($unfilled.Count) {
    throw "[$EnvironmentLabel] Settings still contain <FILL-ME> placeholders. Edit the 'SETTINGS' block at the top of the launcher first."
}
foreach ($s in $SubscriptionId) {
    if ($s -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "[$EnvironmentLabel] '$s' is not a valid subscription ID (GUID)." }
}

# 1b. Collector integrity: show the hash; stop if it differs from the approved one
$collector = Join-Path $PSScriptRoot 'Get-JavaInventory.ps1'
if (-not (Test-Path -LiteralPath $collector)) { throw "Get-JavaInventory.ps1 not found next to the launcher." }
$collectorHash = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash
if ($ExpectedCollectorSha256 -and $collectorHash -ne $ExpectedCollectorSha256.Trim().ToUpperInvariant()) {
    throw "[$EnvironmentLabel] Get-JavaInventory.ps1 has been CHANGED (hash $collectorHash, approved $ExpectedCollectorSha256). Do not run until you know why."
}

# 2. Azure sign-in and subscription visibility
Import-Module Az.Accounts -ErrorAction Stop | Out-Null
if (-not (Get-AzContext)) { throw 'Not signed in to Azure. Run Connect-AzAccount first.' }

$subInfo = foreach ($s in $SubscriptionId) {
    try { Get-AzSubscription -SubscriptionId $s -WarningAction SilentlyContinue -ErrorAction Stop }
    catch { throw "[$EnvironmentLabel] Subscription $s is not visible to $((Get-AzContext).Account.Id). Check the ID and your access." }
}

# 3. Production guard
$looksProd = @($subInfo | Where-Object { $_.Name -match '(?i)prod' -and $_.Name -notmatch '(?i)non[\s_-]?prod|pre[\s_-]?prod|dev|test|uat|qa|sandbox|staging' })

Write-Host ''
Write-Host "==================== Java inventory: $EnvironmentLabel ====================" -ForegroundColor Cyan
foreach ($si in $subInfo) { Write-Host ("  Subscription : {0}  ({1})  state: {2}" -f $si.Name, $si.Id, $si.State) }
if ($ResourceGroupName) { Write-Host ("  Resource groups : {0}" -f ($ResourceGroupName -join ', ')) } else { Write-Host '  Resource groups : ALL in the subscription(s)' }
if ($VMName) { Write-Host ("  VM filter    : {0}" -f ($VMName -join ', ')) } else { Write-Host '  VM filter    : ALL running Windows VMs' }
if ($ExcludeVMName) { Write-Host ("  Excluded VMs : {0}" -f ($ExcludeVMName -join ', ')) } else { Write-Host '  Excluded VMs : none by name (Tier 0 servers are still refused by the collector itself)' }
if ($IncludeTier0Servers) {
    Write-Host '  Tier 0       : DOMAIN CONTROLLERS / CA / AD FS / ENTRA CONNECT WILL BE SCANNED' -ForegroundColor Red
    Write-Host '                 Make sure the SOC and the AD owner approved this, and announced the window.' -ForegroundColor Red
} else {
    Write-Host '  Tier 0       : not scanned (collector refuses DC / CA / AD FS / Entra Connect)'
}
Write-Host ("  Collector    : SHA-256 {0} {1}" -f $collectorHash, $(if ($ExpectedCollectorSha256) { '(matches approved hash)' } else { '(no approved hash set - see SETTINGS)' }))
Write-Host ("  Signed in as : {0}" -f (Get-AzContext).Account.Id)
Write-Host '=======================================================================' -ForegroundColor Cyan
if ($looksProd.Count) {
    Write-Host ("WARNING: subscription name(s) look like PRODUCTION: {0}" -f ($looksProd.Name -join ', ')) -ForegroundColor Red
    Write-Host "         This launcher is for '$EnvironmentLabel'. Check the subscription ID before continuing." -ForegroundColor Red
}

# 4. Confirmation (not needed for a dry run)
if (-not $ListOnly -and (-not $Force -or $looksProd.Count -or $IncludeTier0Servers)) {
    $answer = Read-Host "Type '$EnvironmentLabel' to start the scan (anything else cancels)"
    if ($answer -cne $EnvironmentLabel) { Write-Host 'Cancelled. Nothing was run.' -ForegroundColor Yellow; return }
}

# 5. Run the engine
$engine = Join-Path $PSScriptRoot 'Invoke-JavaInventory.ps1'
$p = @{
    SubscriptionId     = $SubscriptionId
    EnvironmentLabel   = $EnvironmentLabel
    ThrottleLimit      = $ThrottleLimit
    ScanTimeoutMinutes = $ScanTimeoutMinutes
}
if ($ResourceGroupName) { $p.ResourceGroupName = $ResourceGroupName }
if ($VMName)            { $p.VMName = $VMName }
if ($ExcludeVMName)     { $p.ExcludeVMName = $ExcludeVMName }
if ($ExpectedCollectorSha256) { $p.ExpectedCollectorSha256 = $ExpectedCollectorSha256 }
if ($SkipJarScan)       { $p.SkipJarScan = $true }
if ($IncludeTier0Servers) { $p.IncludeTier0Servers = $true }
if ($ListOnly)          { $p.ListOnly = $true }
if ($CleanupOnly)       { $p.CleanupOnly = $true; $p.StateFile = $StateFile }
if ($OutputFolder)      { $p.OutputFolder = $OutputFolder }
& $engine @p
