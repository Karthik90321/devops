<#
.SYNOPSIS
    Java inventory for the DEVAPP environment (DevApp subscription only).

.EXAMPLE
    .\Run-DevApp-Inventory.ps1 -ListOnly                          # dry run: list VMs, run nothing
.EXAMPLE
    .\Run-DevApp-Inventory.ps1 -VMName devapp01                   # pilot on one VM
.EXAMPLE
    .\Run-DevApp-Inventory.ps1                                    # full DevApp run
.EXAMPLE
    .\Run-DevApp-Inventory.ps1 -CleanupOnly -StateFile .\JavaInventory_DevApp_<timestamp>\JavaInventory_State.json
#>
[CmdletBinding()]
param(
    [string[]]$VMName,          # optional override, wildcards allowed
    [switch]$ListOnly,
    [switch]$Force,             # skip the "type DevApp to confirm" prompt (unattended runs)
    [switch]$SkipJarScan,
    [switch]$CleanupOnly,
    [string]$StateFile
)

# =============================== SETTINGS - fill these in ===============================
$Settings = @{
    EnvironmentLabel   = 'DevApp'
    SubscriptionId     = @('<FILL-ME: DevApp subscription ID (GUID)>')   # add more IDs if DevApp spans several subscriptions
    ResourceGroupName  = @()          # optional: e.g. @('rg-devapp-app', 'rg-devapp-web'); empty = all resource groups
    ExcludeVMName      = @()          # VMs never touched, wildcards allowed, e.g. @('devdc01', '*-dc*', '*adfs*')
                                      # PUT YOUR DOMAIN CONTROLLERS / CA / AD FS / ENTRA CONNECT SERVERS HERE
    ExpectedCollectorSha256 = ''      # paste the SHA-256 of the APPROVED Get-JavaInventory.ps1 (the hash in your SOC mail);
                                      # the run then stops if the script was changed. Get it with:
                                      #   (Get-FileHash .\Get-JavaInventory.ps1 -Algorithm SHA256).Hash
    VMName             = @()          # optional default filter, e.g. @('devapp*'); empty = all running Windows VMs
    ThrottleLimit      = 10           # VMs scanned in parallel
    ScanTimeoutMinutes = 45           # disk-scan time budget per VM (max 80)
}
# ========================================================================================

if ($VMName)      { $Settings.VMName = $VMName }
if (-not $Settings.ResourceGroupName.Count) { $Settings.Remove('ResourceGroupName') }
if (-not $Settings.VMName.Count)            { $Settings.Remove('VMName') }
if (-not $Settings.ExcludeVMName.Count)     { $Settings.Remove('ExcludeVMName') }
if (-not $Settings.ExpectedCollectorSha256) { $Settings.Remove('ExpectedCollectorSha256') }
if ($ListOnly)    { $Settings.ListOnly = $true }
if ($Force)       { $Settings.Force = $true }
if ($SkipJarScan) { $Settings.SkipJarScan = $true }
if ($CleanupOnly) { $Settings.CleanupOnly = $true; $Settings.StateFile = $StateFile }

& (Join-Path $PSScriptRoot 'Start-EnvironmentInventory.ps1') @Settings
