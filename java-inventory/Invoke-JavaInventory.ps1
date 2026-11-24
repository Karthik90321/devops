<#
.SYNOPSIS
    Runs the Java inventory (Get-JavaInventory.ps1) on Azure Windows VMs through Azure Run Command and
    produces a consolidated CSV + HTML summary. Leaves the VMs as they were before the run.

.DESCRIPTION
    1. Discovers Windows VMs in the given subscriptions, filtered by resource group / tag / name.
    2. Records, per VM, whether the Run Command extension (Microsoft.CPlat.Core.RunCommandWindows)
       was ALREADY installed.
    3. Runs the read-only collector on each running VM in parallel (throttled).
    4. Pulls the result back in <4 KB chunks (Run Command output limit is 4,096 bytes).
    5. Cleans up on each VM:
         - deletes the collector's temporary result folder (%SystemRoot%\Temp\JavaInventory_<RunId>)
         - deletes downloaded copies of this tool's scripts from the Run Command plugin folder
         - removes the Run Command extension IF it was not present before the run
           (unless -KeepRunCommandExtension is used)
    6. Writes, into -OutputFolder:
         JavaInventory_Findings.csv        every finding, one row each
         JavaInventory_Oracle.csv          Oracle-related rows only (for the licensing team)
         JavaInventory_ServerStatus.csv    one row per VM: scanned / failed / skipped + cleanup result
         JavaInventory_Summary.html        management summary
         JavaInventory_State.json          pre-run VM state (used by -CleanupOnly)

.REQUIREMENTS
    - PowerShell 5.1 or 7.x with Az.Accounts and Az.Compute (Install-Module Az -Scope CurrentUser)
    - Signed in: Connect-AzAccount
    - RBAC: Microsoft.Compute/virtualMachines/runCommand/action (Virtual Machine Contributor or higher)
      plus read on the VMs. Run Command extension removal also needs VM write (Virtual Machine Contributor).
    - VMs need outbound 443 to Azure (AzureCloud service tag) and a Ready VM agent.

.EXAMPLE
    # Dry run: only list which VMs would be scanned
    .\Invoke-JavaInventory.ps1 -SubscriptionId <sub-guid> -TagName Environment -TagValue Dev,NonProd -ListOnly

.EXAMPLE
    # Single-VM pilot
    .\Invoke-JavaInventory.ps1 -SubscriptionId <sub-guid> -ResourceGroupName rg-devapp -VMName devapp01

.EXAMPLE
    # Full run across two subscriptions, Dev + NonProd tagged VMs, 15 at a time
    .\Invoke-JavaInventory.ps1 -SubscriptionId <sub1>,<sub2> -TagName Environment -TagValue Dev,NonProd -ThrottleLimit 15

.EXAMPLE
    # If a run was interrupted: remove leftovers using the saved state file
    .\Invoke-JavaInventory.ps1 -CleanupOnly -StateFile .\JavaInventory_20261120_101500\JavaInventory_State.json
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string[]]$ResourceGroupName,
    [string]$TagName,
    [string[]]$TagValue,
    [string[]]$VMName,                         # wildcards allowed, e.g. 'devapp*'
    [string[]]$ExcludeVMName,                  # wildcards allowed - never touched (e.g. domain controllers)
    [string]$ExpectedCollectorSha256,          # if set, the run stops unless Get-JavaInventory.ps1 has exactly this hash
    [switch]$IncludeTier0Servers,              # NOT recommended: lets the collector scan DCs / CA / AD FS / Entra Connect
    [string]$EnvironmentTagName = 'Environment',
    [ValidatePattern('^[A-Za-z0-9_-]*$')][string]$EnvironmentLabel,   # e.g. DevApp / NonProd - overrides the tag for the Environment column, report title and folder name
    [ValidateRange(1, 50)][int]$ThrottleLimit = 10,
    [ValidateRange(5, 80)][int]$ScanTimeoutMinutes = 45,
    [switch]$SkipJarScan,
    [switch]$KeepRunCommandExtension,
    [switch]$ListOnly,
    [switch]$CleanupOnly,
    [string]$StateFile,
    [string]$OutputFolder
)

$ErrorActionPreference = 'Stop'
$ChunkSize      = 3000                      # base64 chars per chunk (stays well under the 4,096-byte limit)
$JobWatchdogMin = 100                       # Run Command itself times out at 90 min
$MaxChunks      = 400                       # ~1.2 MB compressed per VM; more than this is refused (use -SkipJarScan)
$MaxPayloadMB   = 50                        # decompressed size limit per VM (protects this PC from a hostile VM)
# Names that usually mean a Tier 0 server (domain controller, CA, AD FS, Entra Connect) - used only as a WARNING hint
$Tier0NameRx    = '(?i)(^|[-_.])(dc|adds|addc|rodc|pdc|bdc|adfs|adcs|ca|pki|aadc|aadconnect|adsync|entraconnect)\d*($|[-_.])|domaincontroller'
$CollectorPath  = Join-Path $PSScriptRoot 'Get-JavaInventory.ps1'
$RunId          = [guid]::NewGuid().ToString()
$stamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutputFolder) {
    $prefix = 'JavaInventory_'
    if ($EnvironmentLabel) { $prefix += $EnvironmentLabel + '_' }
    $OutputFolder = Join-Path (Get-Location) ($prefix + $stamp)
}

function Write-Log { param([string]$Msg, [string]$Level = 'INFO')
    $c = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } default { 'Gray' } }
    Write-Host ("[{0}] [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg) -ForegroundColor $c
}

# ------------------------------------------------------------------------------------------------
# Pre-flight
# ------------------------------------------------------------------------------------------------
foreach ($m in 'Az.Accounts', 'Az.Compute') {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m not found. Install with: Install-Module Az -Scope CurrentUser" }
}
Import-Module Az.Accounts, Az.Compute -ErrorAction Stop | Out-Null
if (-not (Test-Path -LiteralPath $CollectorPath)) { throw "Collector not found: $CollectorPath" }
$CollectorHash = (Get-FileHash -LiteralPath $CollectorPath -Algorithm SHA256).Hash
if ($ExpectedCollectorSha256 -and ($CollectorHash -ne $ExpectedCollectorSha256.Trim().ToUpperInvariant())) {
    throw "Get-JavaInventory.ps1 hash mismatch. Expected $ExpectedCollectorSha256 but found $CollectorHash. The script was changed - do not run it until you know why."
}
if (-not (Get-AzContext)) { throw 'Not signed in to Azure. Run Connect-AzAccount first.' }
$null = New-Item -ItemType Directory -Path $OutputFolder -Force
Write-Log "Output folder: $OutputFolder"
Write-Log "Collector SHA-256: $CollectorHash"

# ------------------------------------------------------------------------------------------------
# Discover target VMs (or load them from a state file)
# ------------------------------------------------------------------------------------------------
$contexts = @{}
function Get-SubContext { param([string]$Sub)
    if (-not $contexts.ContainsKey($Sub)) { $contexts[$Sub] = Set-AzContext -SubscriptionId $Sub -ErrorAction Stop -WarningAction SilentlyContinue }
    return $contexts[$Sub]
}
function Get-TagValueCI { param($Tags, [string]$Name)
    if (-not $Tags -or -not $Name) { return '' }
    foreach ($k in $Tags.Keys) { if ($k -ieq $Name) { return [string]$Tags[$k] } }
    return ''
}

$targets = New-Object System.Collections.Generic.List[object]
$status  = @{}     # key -> status object

if ($CleanupOnly) {
    if (-not $StateFile -or -not (Test-Path -LiteralPath $StateFile)) { throw '-CleanupOnly requires -StateFile <path to JavaInventory_State.json>' }
    $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    $RunId = $state.RunId
    foreach ($v in $state.VMs) {
        $targets.Add([pscustomobject]@{ Key = $v.Key; Subscription = $v.Subscription; ResourceGroup = $v.ResourceGroup; Name = $v.Name
            Environment = $v.Environment; ExtensionPreExisting = [bool]$v.ExtensionPreExisting; Context = (Get-SubContext $v.Subscription) })
    }
} else {
    if (-not $SubscriptionId) { $SubscriptionId = @((Get-AzContext).Subscription.Id) }
    foreach ($sub in $SubscriptionId) {
        $ctx = Get-SubContext $sub
        Write-Log "Discovering VMs in subscription $($ctx.Subscription.Name) ($sub)"
        $vms = @(Get-AzVM -Status -DefaultProfile $ctx)
        foreach ($vm in $vms) {
            if ($ResourceGroupName -and ($ResourceGroupName -notcontains $vm.ResourceGroupName)) { continue }
            if ($VMName) { $hit = $false; foreach ($p in $VMName) { if ($vm.Name -like $p) { $hit = $true } }; if (-not $hit) { continue } }
            if ($TagName) {
                $tv = Get-TagValueCI $vm.Tags $TagName
                if (-not $tv) { continue }
                if ($TagValue -and -not ($TagValue | Where-Object { $tv -ieq $_ })) { continue }
            }
            $key = "$sub/$($vm.ResourceGroupName)/$($vm.Name)".ToLowerInvariant()
            if ($EnvironmentLabel) { $envName = $EnvironmentLabel }
            else {
                $envName = Get-TagValueCI $vm.Tags $EnvironmentTagName
                if (-not $envName) { $envName = 'Unknown' }
            }
            $st = [pscustomobject][ordered]@{
                VMName = $vm.Name; ResourceGroup = $vm.ResourceGroupName; Subscription = $ctx.Subscription.Name; Environment = $envName
                OsType = [string]$vm.StorageProfile.OsDisk.OsType; PowerState = [string]$vm.PowerState
                Status = 'Pending'; Detail = ''; Chunks = 0; Findings = 0; ExtensionPreExisting = ''; TempFilesCleaned = ''; ExtensionRemoved = ''
                Tier0Hint = $(if ($vm.Name -match $Tier0NameRx) { 'CHECK: name looks like a Tier 0 server (DC/CA/ADFS/Entra Connect) - add to ExcludeVMName' } else { '' })
            }
            $status[$key] = $st
            if ($ExcludeVMName) {
                $ex = $false; foreach ($p in $ExcludeVMName) { if ($vm.Name -like $p) { $ex = $true } }
                if ($ex) { $st.Status = 'Excluded'; $st.Detail = 'Excluded by ExcludeVMName - nothing was run on this VM'; continue }
            }
            if ($st.OsType -ne 'Windows') { $st.Status = 'Skipped'; $st.Detail = 'Not a Windows VM'; continue }
            if ($st.PowerState -notmatch 'running') { $st.Status = 'Skipped'; $st.Detail = "VM not running ($($st.PowerState)) - not scanned; the VM was left as it is (never started by this tool)"; continue }
            $targets.Add([pscustomobject]@{ Key = $key; Subscription = $sub; ResourceGroup = $vm.ResourceGroupName; Name = $vm.Name
                Environment = $envName; ExtensionPreExisting = $false; Context = $ctx })
        }
    }
}

Write-Log ("Targets: {0} running Windows VM(s); skipped: {1}; excluded: {2}" -f $targets.Count, @($status.Values | Where-Object Status -eq 'Skipped').Count, @($status.Values | Where-Object Status -eq 'Excluded').Count)
$tier0Suspects = @($status.Values | Where-Object { $_.Tier0Hint -and $_.Status -ne 'Excluded' })
foreach ($t0 in $tier0Suspects) { Write-Log ("{0}: {1}" -f $t0.VMName, $t0.Tier0Hint) 'WARN' }
if ($ListOnly) {
    $status.Values | Sort-Object Environment, VMName | Format-Table VMName, ResourceGroup, Environment, OsType, PowerState, Status, Tier0Hint, Detail -AutoSize
    $status.Values | Sort-Object Environment, VMName | Select-Object VMName, ResourceGroup, Subscription, Environment, OsType, PowerState, Status, Tier0Hint, Detail |
        Export-Csv (Join-Path $OutputFolder 'JavaInventory_TargetList.csv') -NoTypeInformation -Encoding UTF8
    Write-Log 'ListOnly: nothing was run on any VM.' 'OK'
    return
}
if ($targets.Count -eq 0) { Write-Log 'No VMs to process.' 'WARN'; return }

# ------------------------------------------------------------------------------------------------
# Record whether the Run Command extension already exists (so we restore the original state)
# ------------------------------------------------------------------------------------------------
if (-not $CleanupOnly) {
    foreach ($t in $targets) {
        $pre = $false
        try {
            $iv = Get-AzVM -ResourceGroupName $t.ResourceGroup -Name $t.Name -Status -DefaultProfile $t.Context
            if (@($iv.Extensions | Where-Object { $_.Type -match 'RunCommandWindows' -or $_.Name -match 'RunCommandWindows' }).Count) { $pre = $true }
        } catch { }
        if (-not $pre) {
            try {
                if (@(Get-AzVMExtension -ResourceGroupName $t.ResourceGroup -VMName $t.Name -DefaultProfile $t.Context |
                      Where-Object { $_.ExtensionType -match 'RunCommandWindows' -or $_.Name -match 'RunCommandWindows' }).Count) { $pre = $true }
            } catch { }
        }
        $t.ExtensionPreExisting = $pre
        $status[$t.Key].ExtensionPreExisting = [string]$pre
    }
    # Persist state so an interrupted run can still be cleaned up (-CleanupOnly -StateFile ...)
    $stateObj = [pscustomobject]@{ RunId = $RunId; Created = (Get-Date).ToString('s')
        VMs = @($targets | Select-Object Key, Subscription, ResourceGroup, Name, Environment, ExtensionPreExisting) }
    $stateObj | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputFolder 'JavaInventory_State.json') -Encoding UTF8
}
if ($CleanupOnly) {
    foreach ($t in $targets) {
        $status[$t.Key] = [pscustomobject][ordered]@{ VMName = $t.Name; ResourceGroup = $t.ResourceGroup; Subscription = $t.Subscription
            Environment = $t.Environment; OsType = 'Windows'; PowerState = ''; Status = 'CleanupOnly'; Detail = ''; Chunks = 0; Findings = 0
            ExtensionPreExisting = [string]$t.ExtensionPreExisting; TempFilesCleaned = ''; ExtensionRemoved = '' }
    }
}

# ------------------------------------------------------------------------------------------------
# Task scheduler: Scan -> Fetch(1..n-1) -> Cleanup -> RemoveExtension   (one task per VM at a time)
# ------------------------------------------------------------------------------------------------
$queue   = New-Object System.Collections.Generic.Queue[object]
$running = @{}
$chunks  = @{}       # key -> string[]
$allFindings = New-Object System.Collections.Generic.List[object]

foreach ($t in $targets) {
    if ($CleanupOnly) { $queue.Enqueue(@{ VM = $t; Kind = 'Cleanup' }) }
    else { $queue.Enqueue(@{ VM = $t; Kind = 'Scan' }) }
}

function Start-VMTask { param($Task)
    $vm = $Task.VM
    $p = @{ ResourceGroupName = $vm.ResourceGroup; VMName = $vm.Name; DefaultProfile = $vm.Context; AsJob = $true; ErrorAction = 'Stop' }
    switch ($Task.Kind) {
        'Scan'      { $p.CommandId = 'RunPowerShellScript'; $p.ScriptPath = $CollectorPath
                      $p.Parameter = @{ Mode = 'Scan'; RunId = $RunId; ScanJars = ([string](-not $SkipJarScan)).ToLower()
                                        MaxScanSeconds = [string]($ScanTimeoutMinutes * 60); ChunkSize = [string]$ChunkSize
                                        AllowTier0 = ([string][bool]$IncludeTier0Servers).ToLower() } }
        'Fetch'     { $p.CommandId = 'RunPowerShellScript'; $p.ScriptPath = $CollectorPath
                      $p.Parameter = @{ Mode = 'Fetch'; RunId = $RunId; ChunkIndex = [string]$Task.Chunk; ChunkSize = [string]$ChunkSize } }
        'Cleanup'   { $p.CommandId = 'RunPowerShellScript'; $p.ScriptPath = $CollectorPath
                      $p.Parameter = @{ Mode = 'Cleanup'; RunId = $RunId } }
        'RemoveExt' { $p.CommandId = 'RemoveRunCommandWindowsExtension' }
    }
    return Invoke-AzVMRunCommand @p
}

function Get-StdStreams { param($Result)
    $r = @($Result | Where-Object { $_ -and $_.PSObject.Properties['Value'] }) | Select-Object -Last 1
    $out = ''; $err = ''
    if ($r) {
        $out = (@($r.Value | Where-Object { $_.Code -match 'StdOut' } | ForEach-Object { $_.Message }) -join "`n")
        $err = (@($r.Value | Where-Object { $_.Code -match 'StdErr' } | ForEach-Object { $_.Message }) -join "`n")
    }
    return @{ Out = $out; Err = $err }
}

function Add-AfterDataTasks { param($VM)
    # Always run Cleanup (removes the temp result folder if one was written, and the downloaded
    # script copies in the Run Command plugin folder); Cleanup then queues extension removal if needed.
    $queue.Enqueue(@{ VM = $VM; Kind = 'Cleanup' })
}

function ConvertFrom-Payload { param([string]$B64)
    $bytes = [Convert]::FromBase64String($B64)
    $in = New-Object System.IO.MemoryStream(, $bytes)
    $gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
    # Read with a hard size limit (a hostile/compromised VM could send a decompression bomb)
    $out = New-Object System.IO.MemoryStream
    $buf = New-Object byte[] 65536
    $limit = $MaxPayloadMB * 1MB
    while (($n = $gz.Read($buf, 0, $buf.Length)) -gt 0) {
        $out.Write($buf, 0, $n)
        if ($out.Length -gt $limit) { $gz.Close(); throw "Result larger than $MaxPayloadMB MB after decompression - refused" }
    }
    $gz.Close()
    $text = [System.Text.Encoding]::UTF8.GetString($out.ToArray()); $out.Dispose()
    return @(($text -split "`n") | Where-Object { $_ } | ConvertFrom-Csv)
}

$totalVMs = $targets.Count
while ($queue.Count -gt 0 -or $running.Count -gt 0) {
    while ($running.Count -lt $ThrottleLimit -and $queue.Count -gt 0) {
        $task = $queue.Dequeue()
        try {
            $job = Start-VMTask $task
            $task.Started = Get-Date
            $running[$job.Id] = @{ Job = $job; Task = $task }
            $label = $task.Kind; if ($task.Kind -eq 'Fetch') { $label = "Fetch chunk $($task.Chunk + 1)" }
            Write-Log ("{0}: {1} started" -f $task.VM.Name, $label)
        } catch {
            $st = $status[$task.VM.Key]
            $st.Status = 'Failed'; $st.Detail = "$($task.Kind) could not start: $($_.Exception.Message)"
            Write-Log "$($task.VM.Name): $($st.Detail)" 'ERROR'
        }
    }
    if ($running.Count -eq 0) { continue }

    $null = Wait-Job -Job @($running.Values | ForEach-Object { $_.Job }) -Any -Timeout 15
    foreach ($id in @($running.Keys)) {
        $entry = $running[$id]; $job = $entry.Job; $task = $entry.Task; $vm = $task.VM; $st = $status[$vm.Key]
        if ($job.State -eq 'Running' -and ((Get-Date) - $task.Started).TotalMinutes -gt $JobWatchdogMin) {
            Stop-Job $job -ErrorAction SilentlyContinue
        }
        if ($job.State -notin 'Completed', 'Failed', 'Stopped') { continue }
        $running.Remove($id)

        $result = $null; $jobError = ''
        try { $result = Receive-Job $job -ErrorAction Stop } catch { $jobError = $_.Exception.Message }
        if ($job.State -eq 'Failed' -and -not $jobError) {
            $jobError = [string]$job.JobStateInfo.Reason
            if (-not $jobError -and $job.ChildJobs -and $job.ChildJobs.Count) { $jobError = [string]$job.ChildJobs[0].JobStateInfo.Reason }
            if (-not $jobError) { $jobError = 'Run Command job failed (no reason returned)' }
        }
        if ($job.State -eq 'Stopped') { $jobError = "Timed out after $JobWatchdogMin minutes" }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        $io = Get-StdStreams $result

        switch ($task.Kind) {
            { $_ -in 'Scan', 'Fetch' } {
                $mk = [regex]::Match([string]$io.Out, 'JINV\|(\d+)\|(\d+)\|([A-Za-z0-9+/=]*)\|JINV')
                if ($jobError -or -not $mk.Success) {
                    $msg = $jobError
                    if (-not $msg) { $msg = 'No inventory data in output. ' + (($io.Out + ' ' + $io.Err).Trim() -replace '\s+', ' ') }
                    if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) }
                    $st.Status = 'Failed'; $st.Detail = "$($task.Kind): $msg"
                    Write-Log "$($vm.Name): $($st.Detail)" 'ERROR'
                    # Still try to clean up whatever may have been created
                    $queue.Enqueue(@{ VM = $vm; Kind = 'Cleanup' })
                    break
                }
                $total = [int]$mk.Groups[1].Value; $idx = [int]$mk.Groups[2].Value; $data = $mk.Groups[3].Value
                if ($total -gt $MaxChunks -or $idx -ge $total) {
                    $st.Status = 'Failed'; $st.Detail = "Result too large ($total chunks, limit $MaxChunks). Re-run this VM with -SkipJarScan."
                    Write-Log "$($vm.Name): $($st.Detail)" 'ERROR'
                    $chunks.Remove($vm.Key)
                    $queue.Enqueue(@{ VM = $vm; Kind = 'Cleanup' })
                    break
                }
                if (-not $chunks.ContainsKey($vm.Key)) { $chunks[$vm.Key] = New-Object string[] $total }
                $chunks[$vm.Key][$idx] = $data
                $st.Chunks = $total
                if ($idx + 1 -lt $total) {
                    $queue.Enqueue(@{ VM = $vm; Kind = 'Fetch'; Chunk = $idx + 1 })
                } else {
                    try {
                        $rows = ConvertFrom-Payload (($chunks[$vm.Key]) -join '')
                        foreach ($r in $rows) {
                            $r | Add-Member -NotePropertyName VMName -NotePropertyValue $vm.Name -Force
                            $r | Add-Member -NotePropertyName Environment -NotePropertyValue $vm.Environment -Force
                            $r | Add-Member -NotePropertyName ResourceGroup -NotePropertyValue $vm.ResourceGroup -Force
                            $r | Add-Member -NotePropertyName Subscription -NotePropertyValue $st.Subscription -Force
                            $allFindings.Add($r)
                        }
                        $javaRows = @($rows | Where-Object { $_.FindingType -ne 'ScanInfo' })
                        $st.Findings = $javaRows.Count
                        $st.Status = 'Completed'
                        $info = $rows | Where-Object FindingType -eq 'ScanInfo' | Select-Object -First 1
                        if ($info -and $info.Details -match 'TimedOut: True') { $st.Status = 'Completed (partial - time budget hit)' }
                        if ($info -and $info.Source -eq 'Excluded') { $st.Status = 'Excluded'; $st.Findings = 0 }
                        $st.Detail = if ($info) { $info.Details } else { '' }
                        Write-Log ("{0}: scan complete - {1} Java-related finding(s)" -f $vm.Name, $javaRows.Count) 'OK'
                    } catch {
                        $st.Status = 'Failed'; $st.Detail = 'Could not decode result: ' + $_.Exception.Message
                        Write-Log "$($vm.Name): $($st.Detail)" 'ERROR'
                    }
                    $chunks.Remove($vm.Key)
                    Add-AfterDataTasks -VM $vm
                }
            }
            'Cleanup' {
                if (-not $jobError -and $io.Out -match 'JINV-CLEANUP\|folders=(\d+)\|scripts=(\d+)') {
                    $st.TempFilesCleaned = "Yes (folders removed: $($matches[1]), script copies removed: $($matches[2]))"
                    $cw = [regex]::Matches([string]$io.Out, 'JINV-CLEANUP-WARN\|([^\r\n]+)')
                    if ($cw.Count) {
                        $st.TempFilesCleaned = 'CHECK - ' + (@($cw | ForEach-Object { $_.Groups[1].Value }) -join '; ')
                        Write-Log "$($vm.Name): cleanup left something for manual review - $($st.TempFilesCleaned)" 'WARN'
                    }
                } else {
                    $st.TempFilesCleaned = 'FAILED - ' + ($jobError + ' ' + $io.Err).Trim()
                    Write-Log "$($vm.Name): cleanup failed - re-run with -CleanupOnly" 'WARN'
                }
                if (-not $vm.ExtensionPreExisting -and -not $KeepRunCommandExtension) { $queue.Enqueue(@{ VM = $vm; Kind = 'RemoveExt' }) }
                else { $st.ExtensionRemoved = 'No (was already installed before this run)'; if ($KeepRunCommandExtension) { $st.ExtensionRemoved = 'No (-KeepRunCommandExtension)' } }
            }
            'RemoveExt' {
                if ($jobError) { $st.ExtensionRemoved = 'FAILED - ' + $jobError; Write-Log "$($vm.Name): extension removal failed" 'WARN' }
                else { $st.ExtensionRemoved = 'Yes (was not installed before this run)' }
                if (-not $st.TempFilesCleaned) { $st.TempFilesCleaned = 'Not needed (no file written)' }
            }
        }
    }
    $done = @($status.Values | Where-Object { $_.Status -notin 'Pending', 'Skipped' }).Count
    Write-Progress -Activity 'Java inventory' -Status "$done of $totalVMs VMs scanned; $($running.Count) task(s) running; $($queue.Count) queued" -PercentComplete ([math]::Min(100, 100 * $done / [math]::Max(1, $totalVMs)))
}
Write-Progress -Activity 'Java inventory' -Completed

# Extension state note for pre-existing extensions where no cleanup task ran
foreach ($t in $targets) {
    $st = $status[$t.Key]
    if (-not $st.ExtensionRemoved) {
        if ($t.ExtensionPreExisting) { $st.ExtensionRemoved = 'No (was already installed before this run)' }
        elseif ($KeepRunCommandExtension) { $st.ExtensionRemoved = 'No (-KeepRunCommandExtension)' }
    }
}

# ------------------------------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------------------------------
$cols = 'Environment', 'VMName', 'ComputerName', 'FindingType', 'Vendor', 'Version', 'MajorVersion', 'UpdateVersion', 'JavaType',
        'Bundled', 'OwningApplication', 'Path', 'IsOracle', 'OracleLicenseRisk', 'LicenseNote', 'Source', 'Details',
        'ResourceGroup', 'Subscription', 'ScanTime'
# SECURITY: values such as folder and program names come from the servers (partly user-controlled).
# A cell starting with = + - @ (or tab/CR) is executed as a formula by Excel, so prefix it with a quote.
function ConvertTo-SafeCsvRow { param([Parameter(ValueFromPipeline)]$Row, [string[]]$Columns)
    process {
        $o = [ordered]@{}
        $names = if ($Columns) { $Columns } else { @($Row.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($c in $names) {
            $v = [string]$Row.$c
            if ($v -match '^[=+\-@\t\r]') { $v = "'" + $v }
            $o[$c] = $v
        }
        [pscustomobject]$o
    }
}
$statusRows = @($status.Values | Sort-Object Environment, VMName)
$statusRows | ConvertTo-SafeCsvRow | Export-Csv (Join-Path $OutputFolder 'JavaInventory_ServerStatus.csv') -NoTypeInformation -Encoding UTF8
if ($CleanupOnly) {
    $statusRows | Format-Table VMName, TempFilesCleaned, ExtensionRemoved -AutoSize
    Write-Log 'Cleanup-only run finished.' 'OK'
    return
}

$sorted = @($allFindings | Sort-Object Environment, VMName, FindingType, Path)
$sorted | ConvertTo-SafeCsvRow -Columns $cols | Export-Csv (Join-Path $OutputFolder 'JavaInventory_Findings.csv') -NoTypeInformation -Encoding UTF8
$oracle = @($sorted | Where-Object { $_.IsOracle -eq 'True' -or ($_.OracleLicenseRisk -and $_.OracleLicenseRisk -ne 'None') })
$oracle | ConvertTo-SafeCsvRow -Columns $cols | Export-Csv (Join-Path $OutputFolder 'JavaInventory_Oracle.csv') -NoTypeInformation -Encoding UTF8

# ---------------- HTML summary ----------------
function E { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
function New-Table { param($Rows, [string[]]$Columns, [string]$Empty = 'None found')
    if (-not $Rows -or @($Rows).Count -eq 0) { return "<p class='muted'>$(E $Empty)</p>" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tw"><table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(E $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = [string]$r.$c
            $cls = ''
            if ($c -eq 'OracleLicenseRisk' -or $c -eq 'Status') { $cls = " class='b-" + ($v -replace '[^A-Za-z]', '') + "'" }
            [void]$sb.Append("<td$cls>$(E $v)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

$installs   = @($sorted | Where-Object FindingType -eq 'Installation')
$oracleInst = @($installs | Where-Object IsOracle -eq 'True')
$highRisk   = @($oracle | Where-Object OracleLicenseRisk -eq 'High')
$bundled    = @($installs | Where-Object Bundled -eq 'True')
$jarBundles = @($sorted | Where-Object FindingType -eq 'JarBundle')
$scanned    = @($statusRows | Where-Object { $_.Status -like 'Completed*' })
$failed     = @($statusRows | Where-Object Status -eq 'Failed')
$skipped    = @($statusRows | Where-Object Status -eq 'Skipped')
$excluded   = @($statusRows | Where-Object Status -eq 'Excluded')
$withJava   = @($installs | Select-Object -ExpandProperty VMName -Unique)

$byVendor = @($installs | Group-Object Vendor, MajorVersion | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{ Vendor = $_.Group[0].Vendor; Major = $_.Group[0].MajorVersion; Installations = $_.Count
        Servers = (@($_.Group | Select-Object -ExpandProperty VMName -Unique) -join ', ') } })

$perServer = @($statusRows | ForEach-Object {
    $n = $_.VMName
    $mine = @($sorted | Where-Object VMName -eq $n)
    [pscustomobject]@{ Environment = $_.Environment; VMName = $n; Status = $_.Status
        Installations = @($mine | Where-Object FindingType -eq 'Installation').Count
        Oracle = @($mine | Where-Object { $_.FindingType -eq 'Installation' -and $_.IsOracle -eq 'True' }).Count
        HighRisk = @($mine | Where-Object OracleLicenseRisk -eq 'High').Count
        Bundled = @($mine | Where-Object { $_.FindingType -eq 'Installation' -and $_.Bundled -eq 'True' }).Count
        JarBundles = @($mine | Where-Object FindingType -eq 'JarBundle').Count
        TempFilesCleaned = $_.TempFilesCleaned; ExtensionRemoved = $_.ExtensionRemoved } })

$riskOrder = @{ 'High' = 0; 'Review' = 1; 'Low' = 2; 'None' = 3 }
$oracleSorted = @($oracle | Sort-Object { $riskOrder[[string]$_.OracleLicenseRisk] }, Environment, VMName)
$scopeText = "Subscriptions: $((@($contexts.Values | ForEach-Object { $_.Subscription.Name }) -join ', '))"
if ($ResourceGroupName) { $scopeText += " | Resource groups: $($ResourceGroupName -join ', ')" }
if ($TagName) { $scopeText += " | Tag: $TagName = $(if ($TagValue) { $TagValue -join ', ' } else { '(any)' })" }
if ($VMName) { $scopeText += " | VM filter: $($VMName -join ', ')" }

$reportTitle = 'Java Inventory Summary'
if ($EnvironmentLabel) { $reportTitle += ' - ' + $EnvironmentLabel }
$card = { param($label, $value, $cls) "<div class='card $cls'><div class='v'>$(E $value)</div><div class='l'>$(E $label)</div></div>" }
$html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(E $reportTitle)</title>
<style>
:root{--bg:#f6f7f9;--fg:#1d2330;--muted:#5d6675;--card:#fff;--line:#dde1e7;--hi:#b42318;--hibg:#fde8e7;--rv:#9a6700;--rvbg:#fff4d6;--lo:#1a7f37;--lobg:#e6f4ea;--acc:#2457c5}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ee;--muted:#9aa3b2;--card:#1d2128;--line:#313742;--hi:#ff8a80;--hibg:#3a1d1c;--rv:#f2c14e;--rvbg:#3a3019;--lo:#6fd08c;--lobg:#1b3324;--acc:#7aa2ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 Segoe UI,system-ui,sans-serif}
main{max-width:1400px;margin:0 auto;padding:24px 16px}
h1{margin:0 0 4px;font-size:24px} h2{margin:32px 0 8px;font-size:18px;border-bottom:1px solid var(--line);padding-bottom:6px}
.muted{color:var(--muted)} .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.card .v{font-size:24px;font-weight:600}.card .l{color:var(--muted);font-size:12px}
.card.hi .v{color:var(--hi)} .card.rv .v{color:var(--rv)}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:12.5px} th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--card);font-weight:600} td{word-break:break-word;max-width:420px}
.b-High{color:var(--hi);background:var(--hibg);font-weight:600}.b-Review{color:var(--rv);background:var(--rvbg);font-weight:600}.b-Low{color:var(--lo);background:var(--lobg)}
.b-Failed{color:var(--hi);font-weight:600}.b-Skipped{color:var(--rv)}
.note{background:var(--card);border-left:4px solid var(--rv);padding:10px 12px;border-radius:4px;margin-top:16px}
</style></head><body><main>
<h1>$(E $reportTitle)</h1>
<div class="muted">Generated $(E (Get-Date -Format 'yyyy-MM-dd HH:mm')) | Run ID $(E $RunId)<br>$(E $scopeText)</div>
<div class="cards">
$(& $card 'VMs in scope' $statusRows.Count '')
$(& $card 'Scanned' $scanned.Count '')
$(& $card 'Failed' $failed.Count $(if ($failed.Count) { 'hi' } else { '' }))
$(& $card 'Skipped (stopped / non-Windows)' $skipped.Count $(if ($skipped.Count) { 'rv' } else { '' }))
$(& $card 'Excluded (Tier 0 / by name)' $excluded.Count '')
$(& $card 'Servers with Java' $withJava.Count '')
$(& $card 'Java installations' $installs.Count '')
$(& $card 'Oracle installations' $oracleInst.Count $(if ($oracleInst.Count) { 'rv' } else { '' }))
$(& $card 'Oracle HIGH licence risk' $highRisk.Count $(if ($highRisk.Count) { 'hi' } else { '' }))
$(& $card 'Bundled Java runtimes' $bundled.Count '')
$(& $card 'Apps bundling JARs' $jarBundles.Count '')
</div>
<div class="note"><b>Licensing caveat:</b> the risk ratings use Oracle licence rules as commonly published (BCL / OTN / NFTC by version).
They are a triage aid, <b>not legal advice</b>. Have your licensing/SAM team confirm every <b>High</b> and <b>Review</b> item against your Oracle contracts.
Skipped and failed servers are <b>not</b> covered, so the inventory is only complete when both counts are zero.
Excluded servers (domain controllers and other Tier 0 servers, or servers excluded by name) are left out by design.</div>

<h2>Oracle licensing findings</h2>
$(New-Table $oracleSorted @('OracleLicenseRisk','Environment','VMName','FindingType','Vendor','Version','JavaType','Bundled','OwningApplication','Path','LicenseNote') 'No Oracle Java found')

<h2>Installations by vendor and major version</h2>
$(New-Table $byVendor @('Vendor','Major','Installations','Servers'))

<h2>Software bundled with Java (embedded runtimes)</h2>
$(New-Table $bundled @('Environment','VMName','OwningApplication','Vendor','Version','JavaType','Path','OracleLicenseRisk'))

<h2>Software bundled with JAR files</h2>
$(New-Table $jarBundles @('Environment','VMName','Path','OwningApplication','Details'))

<h2>All Java installations</h2>
$(New-Table $installs @('Environment','VMName','Vendor','Version','JavaType','Bundled','OwningApplication','Path','OracleLicenseRisk','Source'))

<h2>Other traces (Add/Remove Programs, launcher stubs, orphan registry keys, env vars, processes, services)</h2>
$(New-Table @($sorted | Where-Object { $_.FindingType -in 'InstalledProgram','LauncherOrStub','RegistryTrace','EnvironmentVariable','RunningProcess','Service' }) @('Environment','VMName','FindingType','Vendor','Version','OwningApplication','Path','Details'))

<h2>Per-server status and cleanup</h2>
$(New-Table $perServer @('Environment','VMName','Status','Installations','Oracle','HighRisk','Bundled','JarBundles','TempFilesCleaned','ExtensionRemoved'))

<h2>Failed / skipped / excluded servers</h2>
$(New-Table @($statusRows | Where-Object { $_.Status -in 'Failed','Skipped','Excluded' }) @('Environment','VMName','ResourceGroup','Status','Detail') 'None - every server in scope was scanned')
</main></body></html>
"@
$htmlPath = Join-Path $OutputFolder 'JavaInventory_Summary.html'
Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8

Write-Log ("Done. Scanned {0}, failed {1}, skipped {2}. Java installations: {3} (Oracle: {4}, HIGH risk rows: {5})" -f `
    $scanned.Count, $failed.Count, $skipped.Count, $installs.Count, $oracleInst.Count, $highRisk.Count) 'OK'
$notClean = @($statusRows | Where-Object { $_.TempFilesCleaned -like 'FAILED*' -or $_.ExtensionRemoved -like 'FAILED*' })
if ($notClean.Count) { Write-Log ("Cleanup incomplete on {0} VM(s): {1}. Re-run with -CleanupOnly -StateFile '{2}'" -f $notClean.Count, ($notClean.VMName -join ', '), (Join-Path $OutputFolder 'JavaInventory_State.json')) 'WARN' }
Write-Log "Reports: $OutputFolder"
