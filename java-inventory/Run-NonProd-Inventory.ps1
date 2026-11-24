<#
.SYNOPSIS
    Java inventory for the NON-PROD environment (Non-Prod subscription only).

.EXAMPLE
    .\Run-NonProd-Inventory.ps1 -ListOnly                         # dry run: list VMs, run nothing
.EXAMPLE
    .\Run-NonProd-Inventory.ps1 -VMName np-app01                  # pilot on one VM
.EXAMPLE
    .\Run-NonProd-Inventory.ps1                                   # full Non-Prod run
.EXAMPLE
    .\Run-NonProd-Inventory.ps1 -CleanupOnly -StateFile .\JavaInventory_NonProd_<timestamp>\JavaInventory_State.json
#>
[CmdletBinding()]
param(
    [string[]]$VMName,          # optional override, wildcards allowed
    [switch]$ListOnly,
    [switch]$Force,             # skip the "type NonProd to confirm" prompt (unattended runs)
    [switch]$SkipJarScan,
    [switch]$CleanupOnly,
    [string]$StateFile
)

# =============================== SETTINGS - fill these in ===============================
$Settings = @{
    EnvironmentLabel   = 'NonProd'
    SubscriptionId     = @('<FILL-ME: Non-Prod subscription ID (GUID)>')   # add more IDs if Non-Prod spans several subscriptions
    ResourceGroupName  = @()          # optional: e.g. @('rg-nonprod-app'); empty = all resource groups
    IncludeTier0Servers = $false      # $true = ALSO SCAN domain controllers / CA / AD FS / Entra Connect servers.
                                      # Set to $true ONLY after the SOC and the AD owner approved DC scanning for the
                                      # announced window. With $false the collector refuses those servers.
    ExcludeVMName      = @()          # VMs never touched at all, wildcards allowed, e.g. @('devdc01', '*adfs*')
    ExpectedCollectorSha256 = ''      # paste the SHA-256 of the APPROVED Get-JavaInventory.ps1 (the hash in your SOC mail);
                                      # the run then stops if the script was changed. Get it with:
                                      #   (Get-FileHash .\Get-JavaInventory.ps1 -Algorithm SHA256).Hash
    VMName             = @()          # optional default filter; empty = all running Windows VMs
    ThrottleLimit      = 10           # VMs scanned in parallel
    ScanTimeoutMinutes = 45           # disk-scan time budget per VM (max 80)
}
# ========================================================================================

if ($VMName)      { $Settings.VMName = $VMName }
if (-not $Settings.ResourceGroupName.Count) { $Settings.Remove('ResourceGroupName') }
if (-not $Settings.VMName.Count)            { $Settings.Remove('VMName') }
if (-not $Settings.ExcludeVMName.Count)     { $Settings.Remove('ExcludeVMName') }
if (-not $Settings.ExpectedCollectorSha256) { $Settings.Remove('ExpectedCollectorSha256') }
if (-not $Settings.IncludeTier0Servers)     { $Settings.Remove('IncludeTier0Servers') }
if ($ListOnly)    { $Settings.ListOnly = $true }
if ($Force)       { $Settings.Force = $true }
if ($SkipJarScan) { $Settings.SkipJarScan = $true }
if ($CleanupOnly) { $Settings.CleanupOnly = $true; $Settings.StateFile = $StateFile }

& (Join-Path $PSScriptRoot 'Start-EnvironmentInventory.ps1') @Settings
