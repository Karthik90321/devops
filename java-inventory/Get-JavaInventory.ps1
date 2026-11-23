<#
.SYNOPSIS
    Read-only Java (JDK / JRE / bundled runtime / JAR) inventory collector for Windows Server.
    JINV-TOOL-MARKER (used by the cleanup step to identify this tool's own files - do not remove)

.DESCRIPTION
    Runs ON the target server, normally pushed by Invoke-JavaInventory.ps1 through Azure Run Command
    (executes as SYSTEM). Can also be run locally by an administrator.

    What it inspects (read-only):
      1. Fixed-drive file scan for java.exe / javaw.exe / jvm.dll   (finds bundled/embedded runtimes)
      2. Fixed-drive file scan for *.jar outside Java homes          (finds software bundled with JARs)
      3. Vendor registry keys (JavaSoft, Adoptium, Azul, Microsoft JDK, IBM, BellSoft, SapMachine, ...)
      4. Add/Remove Programs (machine + loaded user hives, 64/32-bit)
      5. JAVA_HOME / JRE_HOME / JDK_HOME / PATH (machine + loaded user hives)
      6. Running java processes and any process that has jvm.dll loaded (e.g. tomcat9.exe, prunsrv.exe)
      7. Windows services referencing Java, plus Apache Procrun (Tomcat) JVM registry settings

    What it NEVER does:
      - It never executes any java.exe it finds (version/vendor come from file metadata + 'release' file).
      - It never installs, changes or deletes anything outside its own temporary work folder.
      - It never loads unloaded user registry hives.
      - It does not compile code (no Add-Type), so nothing is written to the temp/compiler folders.

    Output / footprint:
      - Results are gzip+base64 encoded and written to STDOUT between JINV markers.
      - Only when the result is larger than one Run Command output chunk (4 KB limit) is a single file
        written to  %SystemRoot%\Temp\JavaInventory_<RunId>\JavaInventory.b64  so the orchestrator can
        fetch the remaining chunks; the orchestrator deletes that folder afterwards (-Mode Cleanup).
      - With -LocalCsvPath (manual mode) a readable CSV is written to the path you give - nothing else.

    Command lines of Java processes are captured with secret-looking values masked
    (password/pwd/secret/token/key/credential...=*****).

.PARAMETER Mode
    Scan (default) | Fetch | Cleanup.  Fetch/Cleanup are used internally by the orchestrator.

.NOTES
    Compatible with Windows PowerShell 5.1 (Windows Server 2019 default). All parameters are strings
    because Azure Run Command passes parameters as strings only.
#>
[CmdletBinding()]
param(
    [string]$Mode           = 'Scan',
    [string]$RunId          = '',
    [string]$ScanJars       = 'true',
    [string]$MaxScanSeconds = '3000',
    [string]$ChunkSize      = '3000',
    [string]$ChunkIndex     = '0',
    [string]$LocalCsvPath   = ''
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
Set-StrictMode -Off

# ------------------------------------------------------------------------------------------------
# Common helpers
# ------------------------------------------------------------------------------------------------
if ($RunId -and ($RunId -notmatch '^[A-Za-z0-9-]{1,64}$')) {
    Write-Output 'JINV-ERROR|Invalid RunId'
    exit 1
}
$chunkSz  = [int]$ChunkSize
$WorkRoot = Join-Path $env:SystemRoot 'Temp'
$WorkDir  = if ($RunId) { Join-Path $WorkRoot ("JavaInventory_" + $RunId) } else { $null }
$B64File  = if ($WorkDir) { Join-Path $WorkDir 'JavaInventory.b64' } else { $null }

function Write-Chunk {
    param([string]$Data, [int]$Index, [int]$Size)
    $total = [int][math]::Ceiling($Data.Length / [double]$Size)
    if ($total -lt 1) { $total = 1 }
    $start = $Index * $Size
    $len   = [math]::Min($Size, [math]::Max(0, $Data.Length - $start))
    $part  = if ($len -gt 0) { $Data.Substring($start, $len) } else { '' }
    Write-Output ("JINV|{0}|{1}|{2}|JINV" -f $total, $Index, $part)
}

# ------------------------------------------------------------------------------------------------
# Mode: Fetch  (return chunk N of a previous scan)
# ------------------------------------------------------------------------------------------------
if ($Mode -eq 'Fetch') {
    if (-not $B64File -or -not (Test-Path -LiteralPath $B64File)) {
        Write-Output 'JINV-ERROR|Result file not found (already cleaned up or wrong RunId)'
        exit 1
    }
    $data = [System.IO.File]::ReadAllText($B64File)
    Write-Chunk -Data $data -Index ([int]$ChunkIndex) -Size $chunkSz
    exit 0
}

# ------------------------------------------------------------------------------------------------
# Mode: Cleanup  (remove everything this tool created)
# ------------------------------------------------------------------------------------------------
if ($Mode -eq 'Cleanup') {
    $removed = 0
    # 1. Our work folder(s). Only folders that look like ours AND contain only our result file.
    Get-ChildItem -LiteralPath $WorkRoot -Directory -Filter 'JavaInventory_*' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $items = @(Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue)
            $onlyOurs = ($items.Count -eq 0) -or (@($items | Where-Object { $_.Name -ne 'JavaInventory.b64' }).Count -eq 0)
            if ($onlyOurs) {
                Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path -LiteralPath $_.FullName)) { $removed++ }
            }
        }
    # 2. Copies of this tool's scripts that the Run Command extension downloaded (only files that
    #    carry our marker; the currently running copy cannot delete itself and is skipped).
    $pluginRoot = 'C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows'
    $scriptsRemoved = 0
    if (Test-Path -LiteralPath $pluginRoot) {
        Get-ChildItem -LiteralPath $pluginRoot -Recurse -File -Include *.ps1 -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne $PSCommandPath } |
            ForEach-Object {
                try {
                    $head = [System.IO.File]::ReadAllText($_.FullName)
                    if ($head -match 'JINV-TOOL-MARKER') {
                        Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                        $scriptsRemoved++
                    }
                } catch { }
            }
    }
    Write-Output ("JINV-CLEANUP|folders={0}|scripts={1}" -f $removed, $scriptsRemoved)
    exit 0
}

# ------------------------------------------------------------------------------------------------
# Mode: Scan
# ------------------------------------------------------------------------------------------------
$scanStart   = Get-Date
$doJars      = $ScanJars -match '^(1|true|yes)$'
$deadline    = [DateTime]::UtcNow.AddSeconds([int]$MaxScanSeconds)
$computer    = $env:COMPUTERNAME
$scanTimeIso = (Get-Date).ToString('s')
$findings    = New-Object System.Collections.Generic.List[object]
$warnings    = New-Object System.Collections.Generic.List[string]

function New-Finding {
    param(
        [string]$FindingType, [string]$Path = '', [string]$Vendor = '', [string]$Version = '',
        $MajorVersion = '', $UpdateVersion = '', [string]$JavaType = '', [string]$OwningApplication = '',
        [string]$Bundled = '', [string]$IsOracle = '', [string]$OracleLicenseRisk = '',
        [string]$LicenseNote = '', [string]$Source = '', [string]$Details = ''
    )
    # Single-line values only (keeps the CSV well-formed)
    foreach ($v in 'Path', 'Vendor', 'Version', 'OwningApplication', 'LicenseNote', 'Source', 'Details') {
        $cur = Get-Variable -Name $v -ValueOnly
        if ($cur) { Set-Variable -Name $v -Value (([string]$cur) -replace '[\r\n\t]+', ' ') }
    }
    [pscustomobject][ordered]@{
        ComputerName      = $computer
        FindingType       = $FindingType
        Vendor            = $Vendor
        Version           = $Version
        MajorVersion      = $MajorVersion
        UpdateVersion     = $UpdateVersion
        JavaType          = $JavaType
        Path              = $Path
        OwningApplication = $OwningApplication
        Bundled           = $Bundled
        IsOracle          = $IsOracle
        OracleLicenseRisk = $OracleLicenseRisk
        LicenseNote       = $LicenseNote
        Source            = $Source
        Details           = $Details
        ScanTime          = $scanTimeIso
    }
}

function Protect-CommandLine {
    param([string]$Text)
    if (-not $Text) { return '' }
    # Mask values of anything that looks like a secret:  -Dfoo.password=abc  /  --token abc  /  pwd:abc
    $t = [regex]::Replace($Text, '(?i)((?:pass(?:word|wd)?|pwd|secret|token|apikey|api[._-]?key|credential|keystorepass|truststorepass)[\w.\-]*\s*[=:]\s*)("[^"]*"|\S+)', '$1*****')
    $t = [regex]::Replace($t, '(?i)(--?(?:pass(?:word)?|pwd|secret|token|key)\s+)("[^"]*"|\S+)', '$1*****')
    if ($t.Length -gt 400) { $t = $t.Substring(0, 400) + '...' }
    return $t
}

function Get-NormalizedVendor {
    param([string]$Text)
    if (-not $Text) { return '' }
    if ($Text -match 'GraalVM')                 { return 'Oracle GraalVM / GraalVM' }
    if ($Text -match 'Sun Microsystems')        { return 'Oracle (Sun legacy)' }
    if ($Text -match 'Oracle')                  { return 'Oracle' }
    if ($Text -match 'Adoptium|Temurin|Eclipse'){ return 'Eclipse Adoptium (Temurin)' }
    if ($Text -match 'AdoptOpenJDK')            { return 'AdoptOpenJDK' }
    if ($Text -match 'Amazon|Corretto')         { return 'Amazon Corretto' }
    if ($Text -match 'Azul|Zulu')               { return 'Azul Zulu' }
    if ($Text -match 'Microsoft')               { return 'Microsoft Build of OpenJDK' }
    if ($Text -match 'IBM|Semeru|International Business') { return 'IBM (Semeru/J9)' }
    if ($Text -match 'BellSoft|Liberica')       { return 'BellSoft Liberica' }
    if ($Text -match 'SAP')                     { return 'SAP SapMachine' }
    if ($Text -match 'Red ?Hat')                { return 'Red Hat OpenJDK' }
    if ($Text -match 'JetBrains')               { return 'JetBrains Runtime' }
    if ($Text -match 'ojdkbuild')               { return 'ojdkbuild' }
    return $Text.Trim()
}

function ConvertTo-JavaVersion {
    # Accepts release-file style ("1.8.0_351", "17.0.9", "21.0.2+13") or Windows file versions ("8.0.3510.10", "17.0.9.0")
    param([string]$Text, [switch]$FileVersion)
    $r = @{ Major = ''; Update = ''; Display = '' }
    if (-not $Text) { return $r }
    $v = $Text.Trim().Trim('"')
    if ($FileVersion) {
        $p = $v -split '[.,]' | ForEach-Object { $_.Trim() }
        if ($p.Count -ge 3 -and $p[0] -match '^\d+$' -and $p[2] -match '^\d+$') {
            $maj = [int]$p[0]
            if ($maj -le 8) {
                $upd = [int][math]::Floor([int]$p[2] / 10)
                $r.Major = $maj; $r.Update = $upd; $r.Display = ('1.{0}.0_{1}' -f $maj, $upd)
            } else {
                $r.Major = $maj; $r.Update = [int]$p[2]; $r.Display = ('{0}.{1}.{2}' -f $p[0], $p[1], $p[2])
            }
        }
        return $r
    }
    if ($v -match '^1\.(\d+)\.\d+(?:_(\d+))?') {
        $r.Major = [int]$matches[1]
        $r.Update = if ($matches[2]) { [int]$matches[2] } else { 0 }
    } elseif ($v -match '^(\d+)(?:\.(\d+))?(?:\.(\d+))?') {
        $r.Major = [int]$matches[1]
        $r.Update = if ($matches[3]) { [int]$matches[3] } else { 0 }
    }
    $r.Display = $v
    return $r
}

# ------------------------------------------------------------------------------------------------
# ORACLE LICENSING RULES  -  review with your licensing / SAM team; edit here if your contract differs.
#   BCL  = Binary Code License (free for general-purpose use)
#   OTN  = Oracle Technology Network License (free only for dev/test/personal; production needs subscription)
#   NFTC = No-Fee Terms and Conditions (free, until 1 year after the next LTS release)
# Returns: @(Risk, Note)   Risk = High | Review | Low | None
# ------------------------------------------------------------------------------------------------
function Get-OracleLicenseRisk {
    param($Major, $Update, [string]$Flavor, [bool]$InOracleProduct)
    if ($Flavor -eq 'NotOracle')      { return @('None', 'Non-Oracle distribution') }
    if ($Flavor -eq 'OracleOpenJDK')  { return @('Low', 'Oracle-built OpenJDK (GPLv2+CPE) - no subscription needed; usually end-of-life, patch risk') }
    if ($Flavor -eq 'GraalVM')        { return @('Review', 'GraalVM - Community (GPL) is free; Oracle GraalVM follows NFTC/OTN like Oracle JDK. Confirm edition') }
    if ($InOracleProduct)             { return @('Review', 'Bundled inside an Oracle product - usually covered by that product licence (restricted use). Verify nothing else uses it') }
    if ($Major -eq '' -or $null -eq $Major) { return @('Review', 'Oracle Java with unknown version - verify manually') }
    $m = [int]$Major; $u = if ($Update -eq '' -or $null -eq $Update) { 0 } else { [int]$Update }
    switch ($m) {
        { $_ -le 6 } { if ($u -le 45) { return @('Low', 'Java 6 <= 6u45 public BCL release - free but long EOL (security risk)') } else { return @('High', 'Java 6 > 6u45 is a paid-support-only update - subscription/support contract required') } }
        7  { if ($u -le 80) { return @('Low', 'Java 7 <= 7u80 public BCL release - free but EOL (security risk)') } else { return @('High', 'Java 7 > 7u80 is a paid-support-only update - subscription required') } }
        8  { if ($u -le 202) { return @('Low', 'Java 8 <= 8u202 BCL - free for general purpose use; EOL patch level') } else { return @('High', 'Java 8u211+ is under OTN - production/commercial use requires Oracle Java SE subscription') } }
        { $_ -in 9, 10 } { return @('Low', 'Java 9/10 BCL - free but EOL (security risk)') }
        { $_ -ge 11 -and $_ -le 16 } { return @('High', 'Oracle JDK 11-16 is under OTN - production use requires Oracle Java SE subscription') }
        17 { if ($u -le 12) { return @('Low', 'Oracle JDK 17 <= 17.0.12 under NFTC - free') } else { return @('High', 'Oracle JDK 17.0.13+ is under OTN (NFTC ended Sept 2024) - production use requires subscription') } }
        { $_ -in 18, 19, 20, 22, 23, 24 } { return @('Low', 'Non-LTS Oracle JDK under NFTC - free but EOL (security risk)') }
        21 { if ($u -le 12) { return @('Low', 'Oracle JDK 21 under NFTC - free (NFTC for 21 ends ~Sept 2026; verify boundary)') } else { return @('High', 'Oracle JDK 21 update released after NFTC end (Sept 2026) - likely OTN, verify with Oracle terms') } }
        default { return @('Low', 'Oracle JDK 25+ under NFTC - free (verify current Oracle terms)') }
    }
}

# ------------------------------------------------------------------------------------------------
# 1. Registry: Add/Remove Programs (machine + loaded user hives)
# ------------------------------------------------------------------------------------------------
$null = New-PSDrive -Name JINVHKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue -Scope Script
$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
Get-ChildItem 'JINVHKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object {
    $uninstallRoots += "JINVHKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
}

$allPrograms = New-Object System.Collections.Generic.List[object]
foreach ($root in $uninstallRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $p = Get-ItemProperty $_.PSPath -ErrorAction Stop
            if ($p.DisplayName) {
                $loc = ''
                if ($p.InstallLocation) { $loc = ([string]$p.InstallLocation).Trim().Trim('"').TrimEnd('\') }
                $allPrograms.Add([pscustomobject]@{
                    Name = [string]$p.DisplayName; Version = [string]$p.DisplayVersion; Publisher = [string]$p.Publisher
                    InstallLocation = $loc; Hive = $root
                })
            }
        } catch { }
    }
}
$javaNameRegex = '(?i)\b(java|j2se|j2re|jdk|jre|openjdk|corretto|zulu|temurin|adoptium|adoptopenjdk|liberica|semeru|sapmachine|graalvm)\b'
$javaPrograms  = @($allPrograms | Where-Object { $_.Name -match $javaNameRegex -and $_.Name -notmatch '(?i)javascript' })

# Owner lookup table: non-Java programs with an install location
$ownerTable = @($allPrograms | Where-Object { $_.InstallLocation -and $_.InstallLocation.Length -gt 3 -and $_.Name -notmatch $javaNameRegex } |
               Sort-Object { $_.InstallLocation.Length } -Descending)

function Get-AppRoot {
    param([string]$Path)
    $seg = $Path.TrimEnd('\') -split '\\'
    if ($seg.Count -lt 2) { return $Path }
    $s1 = $seg[1].ToLowerInvariant()
    $n = 2
    if ($s1 -in @('program files', 'program files (x86)', 'programdata')) { $n = 3 }
    elseif ($s1 -eq 'users') {
        if ($seg.Count -gt 3 -and $seg[3] -ieq 'appdata') { $n = 6 }
        elseif ($seg.Count -gt 4 -and $seg[3] -match '^\.(vscode|vscode-server|vscode-insiders|cursor)$' -and $seg[4] -ieq 'extensions') { $n = 6 }   # one group per IDE extension
        elseif ($seg.Count -gt 3 -and $seg[3].StartsWith('.')) { $n = 5 }                                                                     # .jdks\<jdk>, .m2\repository, .gradle\caches ...
        else { $n = 4 }
    }
    elseif ($s1 -in @('apps', 'app', 'applications', 'software', 'tools', 'opt', 'srv', 'data', 'install', 'installs')) { $n = 3 }
    $n = [math]::Min($n, $seg.Count)
    return ($seg[0..($n - 1)] -join '\')
}

function Get-OwningApplication {
    param([string]$Path)
    # Per-user developer tools that bundle or download their own Java (not in Add/Remove Programs)
    $userTools = @(
        @{ Rx = '(?i)\\Users\\([^\\]+)\\\.vscode(?:-server|-insiders)?\\extensions\\([^\\]+)'; Fmt = 'VS Code extension {1} (user {0})' },
        @{ Rx = '(?i)\\Users\\([^\\]+)\\\.cursor\\extensions\\([^\\]+)';                      Fmt = 'Cursor extension {1} (user {0})' },
        @{ Rx = '(?i)\\Users\\([^\\]+)\\\.jdks\\([^\\]+)';                                     Fmt = 'JDK downloaded by IntelliJ/JetBrains IDE: {1} (user {0})' },
        @{ Rx = '(?i)\\Users\\([^\\]+)\\AppData\\Local\\JetBrains\\Toolbox\\apps\\([^\\]+)';  Fmt = 'JetBrains IDE {1} (Toolbox, user {0})' },
        @{ Rx = '(?i)\\Users\\([^\\]+)\\\.p2\\pool\\plugins\\([^\\]+)';                        Fmt = 'Eclipse IDE plugin {1} (user {0})' },
        @{ Rx = '(?i)\\Users\\([^\\]+)\\\.gradle\\jdks\\([^\\]+)';                             Fmt = 'JDK downloaded by Gradle: {1} (user {0})' },
        @{ Rx = '(?i)\\Users\\([^\\]+)\\\.m2\\';                                               Fmt = 'Maven local repository (user {0})' },
        @{ Rx = '(?i)\\Users\\([^\\]+)\\\.sdkman\\candidates\\java\\([^\\]+)';                 Fmt = 'SDKMAN Java {1} (user {0})' }
    )
    foreach ($ut in $userTools) {
        $m = [regex]::Match($Path, $ut.Rx)
        if ($m.Success) {
            $g2 = if ($m.Groups.Count -gt 2) { $m.Groups[2].Value } else { '' }
            return @{ Name = ($ut.Fmt -f $m.Groups[1].Value, $g2); Publisher = '' }
        }
    }
    $pl = $Path.ToLowerInvariant()
    foreach ($o in $ownerTable) {
        $ol = $o.InstallLocation.ToLowerInvariant()
        if ($pl -eq $ol -or $pl.StartsWith($ol + '\')) {
            return @{ Name = ('{0} {1}' -f $o.Name, $o.Version).Trim(); Publisher = $o.Publisher }
        }
    }
    $root = Get-AppRoot $Path
    return @{ Name = ('(folder) ' + $root); Publisher = '' }
}

# ------------------------------------------------------------------------------------------------
# 2. Collect candidate Java homes from every evidence source
# ------------------------------------------------------------------------------------------------
$homes = @{}   # lower-case path -> @{ Path; Sources (list); Details (list) }
function Add-HomeEvidence {
    param([string]$HomePath, [string]$Source, [string]$Detail = '')
    if (-not $HomePath) { return }
    $hp = $HomePath.Trim().Trim('"').TrimEnd('\')
    if ($hp.Length -lt 3) { return }
    $k = $hp.ToLowerInvariant()
    if (-not $homes.ContainsKey($k)) {
        $homes[$k] = @{ Path = $hp; Sources = New-Object System.Collections.Generic.List[string]; Details = New-Object System.Collections.Generic.List[string] }
    }
    if (-not $homes[$k].Sources.Contains($Source)) { $homes[$k].Sources.Add($Source) }
    if ($Detail -and -not $homes[$k].Details.Contains($Detail)) { $homes[$k].Details.Add($Detail) }
}

function Resolve-JavaHome {
    # From a binary path (java.exe / javaw.exe / jvm.dll) return @{ Home; Layout }
    param([string]$File)
    $dir  = Split-Path $File -Parent
    $leaf = Split-Path $File -Leaf
    if ($leaf -ieq 'jvm.dll') { $dir = Split-Path $dir -Parent }      # bin\server -> bin
    if ((Split-Path $dir -Leaf) -ine 'bin') { return @{ Home = (Split-Path $File -Parent); Layout = 'NonStandard' } }
    $h = Split-Path $dir -Parent
    if ((Split-Path $h -Leaf) -ieq 'jre') {                          # JDK 8 style jdk\jre -> fold into jdk
        $parent = Split-Path $h -Parent
        if (Test-Path -LiteralPath (Join-Path $parent 'bin\javac.exe')) { $h = $parent }
    }
    return @{ Home = $h; Layout = 'Standard' }
}

# 2a. Disk walk (pure PowerShell / .NET, read-only)
$binHits   = New-Object System.Collections.Generic.List[string]
$jarDirs   = @{}
$log4jHits = New-Object System.Collections.Generic.List[string]
$dirCount = 0; $deniedCount = 0; $timedOut = $false
$excludeRx = New-Object System.Text.RegularExpressions.Regex('^[A-Za-z]:\\(\$Recycle\.Bin|System Volume Information|Config\.Msi|Windows\\(WinSxS|servicing|SoftwareDistribution|Installer|assembly|Microsoft\.NET|Prefetch|CSC|Logs))(\\|$)', 'IgnoreCase')
$drives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName })

$stack = New-Object System.Collections.Generic.Stack[string]
foreach ($d in $drives) { $stack.Push($d) }
while ($stack.Count -gt 0) {
    $dirCount++
    if (($dirCount % 500) -eq 0 -and [DateTime]::UtcNow -gt $deadline) { $timedOut = $true; break }
    $dir = $stack.Pop()
    $files = $null
    try { $files = [System.IO.Directory]::GetFiles($dir) } catch { $deniedCount++; continue }
    foreach ($f in $files) {
        $n = [System.IO.Path]::GetFileName($f)
        if ($n -eq 'java.exe' -or $n -eq 'javaw.exe' -or $n -eq 'jvm.dll') { $binHits.Add($f) }
        elseif ($doJars -and $n.EndsWith('.jar', [System.StringComparison]::OrdinalIgnoreCase)) {
            $jarDirs[$dir] = 1 + [int]$jarDirs[$dir]
            if ($n -like 'log4j-core-*.jar') { $log4jHits.Add($f) }
        }
    }
    $subs = $null
    try { $subs = [System.IO.Directory]::GetDirectories($dir) } catch { continue }
    foreach ($sd in $subs) {
        try { $a = [System.IO.File]::GetAttributes($sd) } catch { continue }
        if (($a -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }   # skip junctions/symlinks (no loops, no double counting)
        if ($excludeRx.IsMatch($sd)) { continue }
        $stack.Push($sd)
    }
}
if ($timedOut) { $warnings.Add("Disk scan stopped at time budget ($MaxScanSeconds s) - results may be incomplete") }

$stubs = New-Object System.Collections.Generic.List[string]
foreach ($b in $binHits) {
    $r = Resolve-JavaHome $b
    if ($r.Layout -eq 'Standard') { Add-HomeEvidence $r.Home 'Disk' }
    else { $stubs.Add($b) }
}

# 2b. Vendor registry keys
$vendorRoots = @(
    'HKLM:\SOFTWARE\JavaSoft', 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft',
    'HKLM:\SOFTWARE\Eclipse Adoptium', 'HKLM:\SOFTWARE\WOW6432Node\Eclipse Adoptium',
    'HKLM:\SOFTWARE\Eclipse Foundation', 'HKLM:\SOFTWARE\WOW6432Node\Eclipse Foundation',
    'HKLM:\SOFTWARE\AdoptOpenJDK', 'HKLM:\SOFTWARE\WOW6432Node\AdoptOpenJDK',
    'HKLM:\SOFTWARE\Azul Systems', 'HKLM:\SOFTWARE\WOW6432Node\Azul Systems',
    'HKLM:\SOFTWARE\Amazon', 'HKLM:\SOFTWARE\WOW6432Node\Amazon',
    'HKLM:\SOFTWARE\Microsoft\JDK', 'HKLM:\SOFTWARE\IBM', 'HKLM:\SOFTWARE\WOW6432Node\IBM',
    'HKLM:\SOFTWARE\BellSoft', 'HKLM:\SOFTWARE\WOW6432Node\BellSoft',
    'HKLM:\SOFTWARE\SapMachine', 'HKLM:\SOFTWARE\SAP\SapMachine'
)
$registryTraces = New-Object System.Collections.Generic.List[object]
foreach ($vr in $vendorRoots) {
    if (-not (Test-Path $vr)) { continue }
    $keys = @(Get-Item $vr -ErrorAction SilentlyContinue) + @(Get-ChildItem $vr -Recurse -ErrorAction SilentlyContinue)
    foreach ($k in $keys) {
        try { $p = Get-ItemProperty $k.PSPath -ErrorAction Stop } catch { continue }
        foreach ($valName in 'JavaHome', 'InstallationPath', 'Path', 'Home') {
            $val = $p.$valName
            if (-not $val) { continue }
            $val = ([string]$val).Trim().Trim('"').TrimEnd('\')
            if ($vr -match 'Amazon' -and $k.Name -notmatch '(?i)corretto|jdk|java') { continue }
            if ($vr -match 'IBM' -and $k.Name -notmatch '(?i)java|jdk|jre|semeru') { continue }
            $keyShort = $k.Name -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
            if (Test-Path -LiteralPath (Join-Path $val 'bin\java.exe')) {
                Add-HomeEvidence $val 'Registry' $keyShort
            } elseif ($valName -eq 'JavaHome') {
                $registryTraces.Add(@{ Key = $keyShort; Value = $val })
            }
        }
    }
}

# 2c. Environment variables (machine + loaded user hives) and PATH
$envSources = @(@{ Scope = 'Machine'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' })
Get-ChildItem 'JINVHKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object {
    $envSources += @{ Scope = "User:$($_.PSChildName)"; Path = "JINVHKU:\$($_.PSChildName)\Environment" }
}
$envFindings = New-Object System.Collections.Generic.List[object]
foreach ($es in $envSources) {
    if (-not (Test-Path $es.Path)) { continue }
    $p = Get-ItemProperty $es.Path -ErrorAction SilentlyContinue
    if (-not $p) { continue }
    foreach ($vn in 'JAVA_HOME', 'JRE_HOME', 'JDK_HOME') {
        $val = $p.$vn
        if ($val) {
            $val = [Environment]::ExpandEnvironmentVariables([string]$val).Trim().Trim('"').TrimEnd('\')
            $exists = Test-Path -LiteralPath (Join-Path $val 'bin\java.exe')
            if ($exists) { Add-HomeEvidence $val $vn $es.Scope }
            $envFindings.Add(@{ Name = $vn; Value = $val; Scope = $es.Scope; Exists = $exists })
        }
    }
    if ($p.Path) {
        foreach ($entry in ([string]$p.Path -split ';')) {
            if (-not $entry) { continue }
            $e = [Environment]::ExpandEnvironmentVariables($entry).Trim().Trim('"').TrimEnd('\')
            $isJavaish = $e -match '(?i)java|jdk|jre|corretto|zulu|temurin|adoptium|semeru|liberica'
            $hasJava = Test-Path -LiteralPath (Join-Path $e 'java.exe')
            if ($isJavaish -or $hasJava) {
                if ($hasJava -and (Split-Path $e -Leaf) -ieq 'bin') { Add-HomeEvidence (Split-Path $e -Parent) 'PATH' $es.Scope }
                $envFindings.Add(@{ Name = 'PATH entry'; Value = $e; Scope = $es.Scope; Exists = $hasJava })
            }
        }
    }
}

# 2d. Running processes
$procFindings = New-Object System.Collections.Generic.List[object]
try {
    Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -in 'java.exe', 'javaw.exe', 'javaws.exe' } | ForEach-Object {
        $exe = $_.ExecutablePath
        if ($exe) {
            $r = Resolve-JavaHome $exe
            if ($r.Layout -eq 'Standard') { Add-HomeEvidence $r.Home 'RunningProcess' ("PID " + $_.ProcessId) }
        }
        $procFindings.Add(@{ Name = $_.Name; ProcId = $_.ProcessId; Exe = $exe; Cmd = (Protect-CommandLine $_.CommandLine); Via = 'java process' })
    }
} catch { $warnings.Add('Process query failed: ' + $_.Exception.Message) }

# Processes that host a JVM in-process (jvm.dll loaded) e.g. tomcat9.exe / prunsrv.exe / vendor launchers
foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
    if ($proc.Id -in 0, 4) { continue }
    if ($proc.ProcessName -in 'java', 'javaw', 'javaws') { continue }
    try {
        $jvm = $proc.Modules | Where-Object { $_.ModuleName -ieq 'jvm.dll' } | Select-Object -First 1
        if ($jvm) {
            $r = Resolve-JavaHome $jvm.FileName
            if ($r.Layout -eq 'Standard') { Add-HomeEvidence $r.Home 'RunningProcess' ("PID $($proc.Id) $($proc.ProcessName).exe (embedded JVM)") }
            $exePath = ''
            try { $exePath = $proc.MainModule.FileName } catch { }
            $procFindings.Add(@{ Name = "$($proc.ProcessName).exe"; ProcId = $proc.Id; Exe = $exePath; Cmd = ('jvm.dll loaded from ' + $jvm.FileName); Via = 'embedded JVM' })
        }
    } catch { }   # access denied / 32-bit process from 64-bit host - skipped
}

# 2e. Services and Apache Procrun (Tomcat etc.)
$svcFindings = New-Object System.Collections.Generic.List[object]
try {
    Get-CimInstance Win32_Service -ErrorAction Stop |
        Where-Object { $_.PathName -match '(?i)java|jre|jdk|jvm|prunsrv|procrun|tomcat|corretto|zulu|temurin' } |
        ForEach-Object {
            $svcFindings.Add(@{ Name = $_.Name; Display = $_.DisplayName; State = $_.State; StartMode = $_.StartMode; Cmd = (Protect-CommandLine $_.PathName) })
        }
} catch { $warnings.Add('Service query failed: ' + $_.Exception.Message) }

foreach ($pr in 'HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0', 'HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0') {
    if (-not (Test-Path $pr)) { continue }
    Get-ChildItem $pr -ErrorAction SilentlyContinue | ForEach-Object {
        $jk = Join-Path $_.PSPath 'Parameters\Java'
        $jp = Get-ItemProperty $jk -ErrorAction SilentlyContinue
        if ($jp -and $jp.Jvm -and $jp.Jvm -ne 'auto' -and (Test-Path -LiteralPath $jp.Jvm)) {
            $r = Resolve-JavaHome $jp.Jvm
            if ($r.Layout -eq 'Standard') { Add-HomeEvidence $r.Home 'ServiceConfig' ("Procrun service " + $_.PSChildName) }
        }
    }
}

# ------------------------------------------------------------------------------------------------
# 3. Analyse each Java home -> Installation rows
# ------------------------------------------------------------------------------------------------
$standardRx = '(?i)^[a-z]:\\program files( \(x86\))?\\(java|eclipse adoptium|eclipse foundation|adoptopenjdk|amazon corretto|zulu|azul systems|microsoft\\jdk|bellsoft|semeru|ibm\\java|sapmachine|openjdk|redhat|ojdkbuild|graalvm)\\'
$oracleProductRx = '(?i)\\oracle\\middleware|weblogic|wlserver|\\oracle_common\\|\\oracle\\product\\|\\client_\d|dbhome|\\jdeveloper|oraclehome|\\oracle\\(ora|client|instantclient)|\\sqldeveloper\\|\\ords\\|\\odi\\|\\oem\\|agent13c|\\hyperion\\|\\epm|peoplesoft|\\jde\\'
$homeList = @($homes.Values | Where-Object { Test-Path -LiteralPath $_.Path })

foreach ($h in $homeList) {
    $hp = $h.Path
    $release = @{}
    $relFile = Join-Path $hp 'release'
    if (Test-Path -LiteralPath $relFile) {
        Get-Content -LiteralPath $relFile -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match '^\s*([A-Z_]+)\s*=\s*"?(.*?)"?\s*$') { $release[$matches[1]] = $matches[2] }
        }
    }
    $bin = Join-Path $hp 'bin\java.exe'
    if (-not (Test-Path -LiteralPath $bin)) { $bin = Join-Path $hp 'bin\javaw.exe' }
    if (-not (Test-Path -LiteralPath $bin)) {
        $jd = @(Get-ChildItem -LiteralPath (Join-Path $hp 'bin') -Filter jvm.dll -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($jd.Count) { $bin = $jd[0].FullName }
    }
    $fvi = $null
    if (Test-Path -LiteralPath $bin) { try { $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($bin) } catch { } }

    # Vendor
    $vendorRaw = ''
    if ($release['IMPLEMENTOR']) { $vendorRaw = $release['IMPLEMENTOR'] }
    elseif ($fvi -and $fvi.CompanyName) { $vendorRaw = $fvi.CompanyName }
    $vendor = Get-NormalizedVendor $vendorRaw
    if (-not $vendor) { $vendor = Get-NormalizedVendor $hp }
    if (-not $vendor) { $vendor = 'Unknown' }
    if ($release['IMPLEMENTOR_VERSION'] -and $release['IMPLEMENTOR_VERSION'] -match '(?i)corretto') { $vendor = 'Amazon Corretto' }
    if ($release['GRAALVM_VERSION'] -or $hp -match '(?i)graalvm') { $vendor = 'Oracle GraalVM / GraalVM' }

    # Version
    $ver = ConvertTo-JavaVersion $release['JAVA_VERSION']
    if (-not $ver.Major -and $fvi) {
        $ver = ConvertTo-JavaVersion $fvi.FileVersion -FileVersion
        if (-not $ver.Major) { $ver = ConvertTo-JavaVersion $fvi.ProductVersion -FileVersion }
    }
    $verDisplay = $ver.Display
    if ($release['JAVA_RUNTIME_VERSION']) { $verDisplay = $release['JAVA_RUNTIME_VERSION'] }

    # JDK / JRE
    $type = 'JRE'
    if (Test-Path -LiteralPath (Join-Path $hp 'bin\javac.exe')) { $type = 'JDK' }
    elseif ($release['IMAGE_TYPE']) { $type = $release['IMAGE_TYPE'] }
    elseif (-not (Test-Path -LiteralPath (Join-Path $hp 'lib\rt.jar')) -and (Test-Path -LiteralPath (Join-Path $hp 'lib\modules'))) { $type = 'JRE (custom runtime image)' }

    # Bundled vs standalone
    $registeredStandalone = $h.Sources.Contains('Registry')
    $hpl = $hp.ToLowerInvariant()
    foreach ($jp in $javaPrograms) {
        if ($jp.InstallLocation -and $jp.InstallLocation.ToLowerInvariant() -eq $hpl) {
            $registeredStandalone = $true
            if (-not $h.Sources.Contains('Add/Remove Programs')) { $h.Sources.Add('Add/Remove Programs') }
        }
    }
    $isStandard = ($hp + '\') -match $standardRx
    $bundled = -not ($isStandard -or $registeredStandalone)
    $owner = if ($bundled) { Get-OwningApplication $hp } else { @{ Name = 'Standalone Java installation'; Publisher = '' } }

    # Oracle classification
    $isOracle = $vendor -match '^Oracle'
    $flavor = 'NotOracle'
    if ($vendor -match 'GraalVM') { $flavor = 'GraalVM'; $isOracle = $true }
    elseif ($isOracle) {
        $prod = if ($fvi) { ('{0} {1}' -f $fvi.ProductName, $fvi.FileDescription) } else { '' }
        if ($prod -match '(?i)openjdk') { $flavor = 'OracleOpenJDK' }   # jdk.java.net GPL builds
        else { $flavor = 'OracleJDK' }
    }
    $inOracleProduct = $isOracle -and $flavor -eq 'OracleJDK' -and (($hp -match $oracleProductRx) -or ($owner.Publisher -match '(?i)oracle'))
    $risk = Get-OracleLicenseRisk -Major $ver.Major -Update $ver.Update -Flavor $flavor -InOracleProduct $inOracleProduct

    $details = @()
    if ($fvi) { $details += ('File: {0} / {1} / {2}' -f $fvi.CompanyName, $fvi.ProductName, $fvi.FileVersion) }
    if ($release['BUILD_TYPE']) { $details += ('BUILD_TYPE=' + $release['BUILD_TYPE']) }
    if ($h.Details.Count) { $details += ($h.Details -join '; ') }

    $findings.Add((New-Finding -FindingType 'Installation' -Path $hp -Vendor $vendor -Version $verDisplay `
        -MajorVersion $ver.Major -UpdateVersion $ver.Update -JavaType $type -OwningApplication $owner.Name `
        -Bundled ([string]$bundled) -IsOracle ([string]$isOracle) -OracleLicenseRisk $risk[0] -LicenseNote $risk[1] `
        -Source ($h.Sources -join ';') -Details ($details -join ' | ')))
}

# Launcher stubs / non-standard binaries (e.g. C:\ProgramData\Oracle\Java\javapath, System32\java.exe)
foreach ($s in $stubs) {
    $fvi = $null; try { $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($s) } catch { }
    $vendor = if ($fvi) { Get-NormalizedVendor $fvi.CompanyName } else { '' }
    $ver = if ($fvi) { ConvertTo-JavaVersion $fvi.FileVersion -FileVersion } else { @{ Major = ''; Update = ''; Display = '' } }
    $isOracle = $vendor -match '^Oracle'
    $findings.Add((New-Finding -FindingType 'LauncherOrStub' -Path $s -Vendor $vendor -Version $ver.Display `
        -MajorVersion $ver.Major -UpdateVersion $ver.Update -IsOracle ([string]$isOracle) `
        -OracleLicenseRisk ($(if ($isOracle) { 'Review' } else { 'None' })) `
        -LicenseNote ($(if ($isOracle) { 'Oracle installer launcher/stub - evidence that Oracle Java is or was installed' } else { '' })) `
        -OwningApplication ((Get-OwningApplication $s).Name) -Source 'Disk' `
        -Details ($(if ($fvi) { '{0} / {1}' -f $fvi.ProductName, $fvi.FileDescription } else { '' }))))
}

# Add/Remove Programs entries
foreach ($jp in $javaPrograms) {
    $vendor = Get-NormalizedVendor ('{0} {1}' -f $jp.Publisher, $jp.Name)
    # Oracle MSI DisplayVersion uses file-version style ("8.0.3510.10" = 8u351, "17.0.9.0" = 17.0.9)
    if ($jp.Version -match '^\d+\.\d+\.\d+\.\d+$') { $ver = ConvertTo-JavaVersion $jp.Version -FileVersion }
    else { $ver = ConvertTo-JavaVersion $jp.Version }
    if ($jp.Name -match '(?i)\b(\d+)\s+Update\s+(\d+)') { $ver.Major = [int]$matches[1]; $ver.Update = [int]$matches[2] }
    $isOracle = ($jp.Publisher -match '(?i)oracle|sun micro') -or ($jp.Name -match '(?i)^java(\(tm\))?\s*(se\s*)?(\d|development|runtime|auto updater|platform)')
    $isOracle = $isOracle -and ($jp.Name -notmatch '(?i)openjdk|corretto|zulu|temurin|adoptium|liberica|semeru|sapmachine|microsoft')
    $risk = if ($isOracle -and $jp.Name -notmatch '(?i)auto updater') { Get-OracleLicenseRisk -Major $ver.Major -Update $ver.Update -Flavor 'OracleJDK' -InOracleProduct $false } else { @($(if ($isOracle) { 'Review' } else { 'None' }), '') }
    $exists = if ($jp.InstallLocation) { [string](Test-Path -LiteralPath $jp.InstallLocation) } else { 'Unknown' }
    $findings.Add((New-Finding -FindingType 'InstalledProgram' -Path $jp.InstallLocation -Vendor $vendor -Version $jp.Version `
        -MajorVersion $ver.Major -UpdateVersion $ver.Update -IsOracle ([string]$isOracle) -OracleLicenseRisk $risk[0] -LicenseNote $risk[1] `
        -OwningApplication $jp.Name -Source 'Add/Remove Programs' `
        -Details ('Publisher: {0}; InstallLocationExists: {1}; Hive: {2}' -f $jp.Publisher, $exists, ($jp.Hive -replace '^JINVHKU:', 'HKU'))))
}

# Orphan registry traces (JavaHome points to a folder that no longer exists)
foreach ($t in $registryTraces) {
    $findings.Add((New-Finding -FindingType 'RegistryTrace' -Path $t.Value -Vendor (Get-NormalizedVendor $t.Key) `
        -IsOracle ([string]($t.Key -match 'JavaSoft')) -OracleLicenseRisk 'Review' `
        -LicenseNote 'Registry entry points to a missing folder - leftover from an uninstalled Java' -Source 'Registry' -Details $t.Key))
}

# Environment variables
foreach ($e in $envFindings) {
    $findings.Add((New-Finding -FindingType 'EnvironmentVariable' -Path $e.Value -Source $e.Name `
        -Details ('Scope: {0}; Target exists: {1}' -f ($e.Scope -replace '^User:', 'User SID '), $e.Exists)))
}

# Processes
foreach ($p in $procFindings) {
    $findings.Add((New-Finding -FindingType 'RunningProcess' -Path $p.Exe -OwningApplication $p.Name -Source $p.Via `
        -Details ('PID {0}; {1}' -f $p.ProcId, $p.Cmd)))
}

# Services
foreach ($s in $svcFindings) {
    $findings.Add((New-Finding -FindingType 'Service' -Path $s.Cmd -OwningApplication ('{0} ({1})' -f $s.Display, $s.Name) `
        -Source 'Win32_Service' -Details ('State: {0}; StartMode: {1}' -f $s.State, $s.StartMode)))
}

# JAR bundles (outside Java homes), grouped by application root
if ($doJars -and $jarDirs.Count) {
    $homePrefixes = @($homeList | ForEach-Object { $_.Path.ToLowerInvariant() + '\' })
    $groups = @{}
    foreach ($jd in $jarDirs.Keys) {
        $jdl = $jd.ToLowerInvariant() + '\'
        $inHome = $false
        foreach ($hpx in $homePrefixes) { if ($jdl.StartsWith($hpx)) { $inHome = $true; break } }
        if ($inHome) { continue }
        $root = Get-AppRoot $jd
        if (-not $groups.ContainsKey($root)) { $groups[$root] = @{ Jars = 0; Dirs = 0; Sample = $jd } }
        $groups[$root].Jars += $jarDirs[$jd]
        $groups[$root].Dirs++
    }
    foreach ($g in $groups.Keys) {
        $gl = $g.ToLowerInvariant()
        $l4j = @($log4jHits | Where-Object { $_.ToLowerInvariant().StartsWith($gl) } | ForEach-Object {
            if ([System.IO.Path]::GetFileName($_) -match 'log4j-core-([\d.]+[\w.-]*)\.jar') { $matches[1] } } | Sort-Object -Unique)
        $det = '{0} JAR file(s) in {1} folder(s); e.g. {2}' -f $groups[$g].Jars, $groups[$g].Dirs, $groups[$g].Sample
        if ($l4j.Count) { $det += ('; log4j-core versions: ' + ($l4j -join ', ')) }
        $findings.Add((New-Finding -FindingType 'JarBundle' -Path $g -OwningApplication ((Get-OwningApplication $g).Name) -Source 'Disk' -Details $det))
    }
}

# Scan info row (always present - proves the server was scanned even if no Java was found)
$elapsed = [int]((Get-Date) - $scanStart).TotalSeconds
$os = ''
try { $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }
$findings.Add((New-Finding -FindingType 'ScanInfo' -Path ($drives -join ',') -Source 'Collector' `
    -Details ('OS: {0}; Directories scanned: {1}; Access denied: {2}; Elapsed: {3}s; TimedOut: {4}; JarScan: {5}; Warnings: {6}' -f `
        $os, $dirCount, $deniedCount, $elapsed, $timedOut, $doJars, ($warnings -join ' / '))))

Remove-PSDrive -Name JINVHKU -ErrorAction SilentlyContinue

# ------------------------------------------------------------------------------------------------
# 4. Output
# ------------------------------------------------------------------------------------------------
if ($LocalCsvPath) {
    $findings | Export-Csv -LiteralPath $LocalCsvPath -NoTypeInformation -Encoding UTF8
    Write-Output ("Wrote {0} findings to {1}" -f $findings.Count, $LocalCsvPath)
    if (-not $RunId) { exit 0 }
}

$csvText = ($findings | ConvertTo-Csv -NoTypeInformation) -join "`n"
$bytes   = [System.Text.Encoding]::UTF8.GetBytes($csvText)
$ms = New-Object System.IO.MemoryStream
$gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$gz.Write($bytes, 0, $bytes.Length); $gz.Close()
$b64 = [Convert]::ToBase64String($ms.ToArray())
$ms.Dispose()

if ($b64.Length -gt $chunkSz) {
    if (-not $RunId) {
        Write-Output 'JINV-ERROR|Result exceeds one chunk and no RunId was given; use -LocalCsvPath for manual runs'
        exit 1
    }
    # Multi-chunk: persist once so the orchestrator can fetch the remaining parts, then it runs Cleanup.
    $null = New-Item -ItemType Directory -Path $WorkDir -Force
    [System.IO.File]::WriteAllText($B64File, $b64)
}
Write-Chunk -Data $b64 -Index 0 -Size $chunkSz
exit 0
