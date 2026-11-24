# Java Inventory for Azure Windows VMs (Dev / Non-Prod)

These scripts find every trace of Java on Windows Server 2019 VMs in Azure. That covers standalone JDKs and JREs, Java runtimes bundled inside other software, and software that ships JAR files. Each finding gets an **Oracle licensing risk** rating.

The scan works through **Azure Run Command**, so you don't need WinRM, RDP or open ports. It is **read-only** and **cleans up after itself**.

| File | Runs where | Purpose |
|---|---|---|
| `Run-DevApp-Inventory.ps1` | Your workstation or Cloud Shell | **Launcher for DevApp.** Holds only the DevApp subscription settings |
| `Run-NonProd-Inventory.ps1` | Your workstation or Cloud Shell | **Launcher for Non-Prod.** Holds only the Non-Prod subscription settings |
| `Start-EnvironmentInventory.ps1` | Called by both launchers | Checks the settings, warns if a subscription looks like production, shows what will be scanned and asks you to confirm |
| `Invoke-JavaInventory.ps1` | Called by the launchers | The shared engine: finds the VMs, runs the scan in parallel, collects results, cleans up and builds the reports |
| `Get-JavaInventory.ps1` | On each VM, as SYSTEM, via Run Command | Read-only collector, also used for the fetch and cleanup steps |

---

## 1. What it detects

| Finding type | Meaning |
|---|---|
| `Installation` | A real Java home (folder with `bin\java.exe` / `jvm.dll`). Shows vendor, version, JDK or JRE, **Bundled** yes/no, owning application, licence risk |
| `LauncherOrStub` | `java.exe` outside a normal Java folder, e.g. `C:\ProgramData\Oracle\Java\javapath` or `System32`. Proof that Oracle Java is or was installed |
| `InstalledProgram` | Java-related Add/Remove Programs entries, for the machine and logged-in users |
| `RegistryTrace` | A vendor registry key pointing to a folder that no longer exists, left behind by an uninstall |
| `EnvironmentVariable` | `JAVA_HOME`, `JRE_HOME`, `JDK_HOME` and Java-related `PATH` entries, for the machine and loaded user profiles |
| `RunningProcess` | Running `java.exe` / `javaw.exe`, plus any process with `jvm.dll` loaded (Tomcat, `prunsrv`, vendor launchers). Secrets in command lines are masked |
| `Service` | Windows services whose command line references Java, Tomcat or Procrun |
| `JarBundle` | Applications that contain JAR files outside a Java home, grouped by application folder, with log4j-core versions if found |
| `ScanInfo` | One per server: drives, directories scanned, access-denied count, run time, and whether the time budget was hit |

**How the script tells vendors apart:**
- It reads `release` file fields (`IMPLEMENTOR`, `JAVA_VERSION`) and the file version info of `java.exe` / `jvm.dll`.
- It never runs `java.exe`.
- Oracle JDK (commercial) is distinguished from Oracle-built OpenJDK (GPL, free) by the binary's product name.

**Bundled runtimes:** a Java runtime counts as **Bundled** when it isn't in a standard vendor folder and isn't registered as a standalone install. The owning application comes from the Add/Remove Programs install location, falling back to the application folder.

**Per-user developer tools:** the scan covers every user profile under `C:\Users`, including users who aren't logged in and hidden dot-folders. Runtimes that IDEs bundle or download are named after their tool. Examples:
- VS Code or Cursor extensions, e.g. SonarLint or Red Hat Java under `.vscode\extensions\...`
- JDKs downloaded by IntelliJ (`.jdks`) or Gradle (`.gradle\jdks`)
- JetBrains Toolbox IDEs
- Eclipse plugins (`.p2`)
- SDKMAN
- the Maven repository (`.m2`)

Each user's copy is reported separately.

**Not detected:** Java runtimes still packed inside archives (`.zip`, `.tar`, `.tar.gz`, `.msi`, `.war`/`.ear` files) that have never been extracted. Only extracted folders are visible. A JDK installer or zip sitting in a Downloads folder isn't reported, and under Oracle's terms it usually doesn't count as a deployment either. Delete such files if they are Oracle.

## 2. Oracle licence risk rules (triage only, not legal advice)

| Oracle version | Rating | Why |
|---|---|---|
| 8u202 and earlier, 7u80 and earlier, 6u45 and earlier, 9, 10 | Low | BCL licence: free, but end-of-life |
| **8u211 and later** | **High** | OTN licence: production use needs an Oracle Java SE subscription |
| **11 to 16** | **High** | OTN |
| 17.0.0 to 17.0.12 | Low | NFTC |
| **17.0.13 and later** | **High** | OTN (NFTC for 17 ended September 2024) |
| 21 up to 21.0.12 | Low | NFTC. The NFTC window for 21 ends around September 2026, so **verify where the boundary falls** |
| 21.0.13 and later | High | Likely OTN. Verify |
| Non-LTS 18–24 (except 21), 25 and later | Low | NFTC |
| Oracle JDK inside an Oracle product (WebLogic, DB client and so on) | Review | Usually covered by that product's restricted-use licence |
| GraalVM | Review | Community edition is free; Oracle GraalVM follows NFTC/OTN |
| Oracle-built OpenJDK | Low | GPL |

The rules live in `Get-OracleLicenseRisk` in `Get-JavaInventory.ps1`. **Have your licensing or SAM team confirm them**, then edit the function if your contract differs.

## 3. Footprint: what changes on the VM

| Item | What happens |
|---|---|
| Temporary result file `%SystemRoot%\Temp\JavaInventory_<RunId>\JavaInventory.b64` | Written only when the result is bigger than about 3 KB (it is needed to get around the 4 KB Run Command output limit). The folder is SYSTEM/Administrators-only. **Deleted** by the cleanup step (exact folder only) |
| Run Command extension `Microsoft.CPlat.Core.RunCommandWindows` | Azure installs it on first use. If it **was not** on the VM before, the script **removes** it at the end. If it **was** there before, it is left as it was |
| Downloaded copies of the scripts in `C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\...` | Deleted by the cleanup step, or removed together with the extension |
| Anything else | Nothing is installed, changed or deleted. No user hives are loaded and no code is compiled |

**What can't be undone, by design:**
- The Run Command extension's own logs under `C:\WindowsAzure\Logs\Plugins\...`.
- Windows event logs and PowerShell logs.
- Azure Activity Log entries.
- On VMs where the extension already existed, one copy of the cleanup script itself, because a running script can't delete itself. It contains no data.

These are audit records, and deleting them would be a security problem.

## 3a. Security review: how Defender or EDR may see this tool

| Behaviour | How the tool limits it | What your SOC may see |
|---|---|---|
| Azure Run Command runs PowerShell as SYSTEM on many VMs | Required by the design. It is a documented Azure feature | Defender for Cloud / Defender for Servers can raise **Run Command usage** alerts. **Tell the SOC the run window in advance** |
| Process inspection | **There is no listing of all processes.** `java.exe`/`javaw.exe` processes are picked **by name**, and only their command lines are read. Processes hosting an embedded JVM are found through the **services list** (read from the registry). Their DLL list is read only if the service's .exe sits in the same application folder as a Java runtime already found on disk, or is a Procrun/Tomcat wrapper. **Nothing under `%SystemRoot%` is ever opened**, so LSASS, system processes and security agents are never touched | Nothing unusual. *Versions before this change opened every process including LSASS, which raised an LSASS alert on a domain controller* |
| Tier 0 servers (domain controllers, AD CS certificate authorities, AD FS, Entra/Azure AD Connect) | The collector checks the server's role and services first. On a Tier 0 server it **exits without scanning** and the server is reported as **Excluded**. Also list such servers in `ExcludeVMName` so nothing at all runs on them | One Run Command on that server (if it isn't in `ExcludeVMName`), lasting a few seconds |
| Network paths from user-writable settings (`JAVA_HOME=\\server\share`) | **Only local drive paths are ever touched.** UNC and device paths are ignored, so SYSTEM never authenticates to another machine | Nothing |
| Temp folder in `C:\Windows\Temp` (writable by users) | It is created fresh with SYSTEM + Administrators-only permissions. The script refuses to use it if it already exists or is a link. Cleanup deletes only this run's exact folder, never follows links, and never deletes recursively | File create/delete events |
| Script tampering on your PC | The launcher shows the collector's SHA-256. Set `ExpectedCollectorSha256` in the launcher and the run **stops** if the script has changed | Nothing |
| WDAC / AppLocker (Constrained Language Mode) | The collector detects it and stops cleanly with a clear message | Nothing |
| CSV opened in Excel | Cells starting with `= + - @` are prefixed with `'`, which blocks formula injection | Nothing |
| Recursive scan of every fixed drive and user profile | Read-only metadata (names and file version info). File contents are never opened, except Java's small `release` text file | Possibly a "file and directory discovery" signal in advanced hunting. Low severity |
| Results gzip-compressed and base64-encoded in the output | Encode only. The script never decodes data and runs it (no `Invoke-Expression`, no downloads, no `Add-Type`) | Unlikely to alert. Mention it to the SOC so it isn't mistaken for data exfiltration |
| Deleting its own temp file and script copies after the run | Deletes only files carrying the tool's marker, or its own temp folder. Logs are never touched | File deletion events. Covered by telling the SOC in advance |
| Process command lines collected (Java processes only) | Secret-looking values are masked: `password=`, `token=`, `AccountKey=`, `SharedAccessKey=`, SAS `sig=`, `client_secret=`, `user:pass@` in URLs, JDBC `user/pass@`, `Bearer`/`Basic` tokens | None |
| Unsigned scripts | Run Command runs them with its own execution policy | If **WDAC or AppLocker** is enforced, PowerShell drops to Constrained Language Mode and the collector **fails** (it uses .NET file APIs). Fix: sign the scripts with your organisation's code-signing certificate |

**The report is internal-confidential.** It contains server names, user profile names (taken from paths) and masked command lines. Share it only with the people who need it.

## 4. Prerequisites

- PowerShell 5.1 or 7.x with the Az module: `Install-Module Az -Scope CurrentUser`
- Signed in with `Connect-AzAccount`
- The **Virtual Machine Contributor** role (it includes `Microsoft.Compute/virtualMachines/runCommand/action` and the right to remove the extension) on the target VMs or resource groups
- Each VM must be running, have a **Ready** VM agent, and allow **outbound 443 to Azure** (the `AzureCloud` service tag)

## 5. How to run it (start with a pilot)

### 5a. Per environment, the normal way

DevApp and Non-Prod are in **separate subscriptions** and are run **separately**. Each launcher scans only its own subscription and writes its own report folder: `JavaInventory_DevApp_<timestamp>\` or `JavaInventory_NonProd_<timestamp>\`. Both launchers use the same engine, so the two reports are always comparable.

**One-time setup:** open each launcher and replace the `<FILL-ME>` value in its `SETTINGS` block with that environment's subscription ID. The launchers won't run while a placeholder is left. **Don't commit real subscription IDs** to a shared repo unless your team is fine with that.

```powershell
Connect-AzAccount
```

DevApp:

```powershell
.\Run-DevApp-Inventory.ps1 -ListOnly
```

```powershell
.\Run-DevApp-Inventory.ps1 -VMName <one-devapp-vm>
```

```powershell
.\Run-DevApp-Inventory.ps1
```

Non-Prod:

```powershell
.\Run-NonProd-Inventory.ps1 -ListOnly
```

```powershell
.\Run-NonProd-Inventory.ps1 -VMName <one-nonprod-vm>
```

```powershell
.\Run-NonProd-Inventory.ps1
```

**What each launcher checks before it runs anything:**
- The subscription ID is a valid GUID and your account can see it.
- The subscription name doesn't look like **production**. If it does, you see a red warning and the confirmation prompt can't be skipped.
- You see the subscription, resource groups, VM filter and signed-in account, then type `DevApp` or `NonProd` to confirm. `-ListOnly` needs no confirmation because it runs nothing. Use `-Force` for unattended runs.

### 5b. Using the engine directly

```powershell
# 0. Sign in
Connect-AzAccount
```

```powershell
# 1. Dry run: list which VMs would be scanned (nothing runs on any VM)
.\Invoke-JavaInventory.ps1 -SubscriptionId <sub-id> -TagName Environment -TagValue Dev,NonProd -ListOnly
```

```powershell
# 2. Pilot on ONE dev VM, then check the CSV and HTML
.\Invoke-JavaInventory.ps1 -SubscriptionId <sub-id> -ResourceGroupName <rg> -VMName <devapp-vm-name>
```

```powershell
# 3. Full run (dev app + non-prod)
.\Invoke-JavaInventory.ps1 -SubscriptionId <sub1>,<sub2> -TagName Environment -TagValue Dev,NonProd -ThrottleLimit 10
```

```powershell
# If a run is interrupted: remove leftovers
.\Invoke-JavaInventory.ps1 -CleanupOnly -StateFile .\JavaInventory_<timestamp>\JavaInventory_State.json
```

Useful switches:

| Switch | Effect |
|---|---|
| `-VMName 'devapp*'` | Filter by VM name; wildcards are allowed |
| `-ResourceGroupName` | Limit the scan to specific resource groups |
| `-EnvironmentLabel` | Fixed label for the Environment column, report title and folder name. The launchers set it to `DevApp` or `NonProd` |
| `-EnvironmentTagName` | The tag used for the Environment column when no `-EnvironmentLabel` is given. Default: `Environment` |
| `-ExcludeVMName` | VMs that are never touched, wildcards allowed. **Put your domain controllers and other Tier 0 servers here.** The launchers have it in `SETTINGS` |
| `-ExpectedCollectorSha256` | The run stops unless `Get-JavaInventory.ps1` has exactly this hash. The launchers have it in `SETTINGS` |
| `-IncludeTier0Servers` | **Not recommended.** Lets the collector scan domain controllers, CA, AD FS and Entra Connect servers |
| `-ScanTimeoutMinutes` | Time limit for the disk scan. Default 45, hard maximum 80 (Run Command stops at 90 minutes) |
| `-SkipJarScan` | Skip the JAR scan. It is a little faster but won't show software bundled with JARs |
| `-KeepRunCommandExtension` | Don't remove the extension even if this run installed it |

## 6. Output (in `.\JavaInventory_<DevApp|NonProd>_<timestamp>\`)

### `Share\`: the files you send to the onshore team (Java information only)

| File | Content |
|---|---|
| `JavaInventory_<Env>_Summary.html` | Summary cards, Oracle findings (High first), vendor/version pivot, bundled runtimes, JAR bundles, all installations, other Java traces, and **server coverage** |
| `JavaInventory_<Env>_Java_Findings.csv` | One row per Java finding. Columns: Environment, VMName, FindingType, Vendor, Version, MajorVersion, UpdateVersion, JavaType, Bundled, OwningApplication, Path, IsOracle, OracleLicenseRisk, LicenseNote, Evidence, JarDetails |
| `JavaInventory_<Env>_Oracle.csv` | Oracle-related rows only, High first |
| `JavaInventory_<Env>_Coverage.csv` | One row per VM: **Scanned** / **Not scanned** (with a plain reason) and Java/Oracle counts. Without it, "no Java found" and "not checked" would look the same |

**Left out of the Share package:**
- the scan technical row (OS, folder counts, time taken)
- Run ID, subscription and resource group names
- process IDs and **command lines**
- registry hive paths, user SIDs, file metadata
- service arguments (only the service's .exe path is kept)
- cleanup and extension status
- **user profile names**: `C:\Users\john.doe\...` becomes `C:\Users\<user>\...`. Use `-ShareKeepUserNames` with the engine if the onshore team needs to know whose copy it is

### Main folder: INTERNAL, for you only, do not share

| File | For |
|---|---|
| `JavaInventory_Summary.html` | Full internal summary, including per-server technical status and cleanup results |
| `JavaInventory_Findings.csv` | Every finding with all technical detail (Details, ScanInfo rows, Subscription, ResourceGroup) |
| `JavaInventory_Oracle.csv` | Oracle rows with full detail |
| `JavaInventory_ServerStatus.csv` | One row per VM: technical status, `TempFilesCleaned`, `ExtensionRemoved`. **This is your proof that the cleanup worked** |
| `JavaInventory_State.json` | The pre-run state, needed for `-CleanupOnly` |

> **The inventory is complete only when Failed = 0 and Skipped = 0.** Excluded servers (Tier 0, or excluded by name) are left out on purpose and listed in the report.
>
> **The `-ListOnly` dry run prints a warning for VM names that look like Tier 0 servers** (`dc`, `adfs`, `ca`, `aadc` ...). Check those, and add them to `ExcludeVMName` before the real run. Stopped VMs are skipped because Run Command can't reach them. **The tool never starts, stops or changes any VM.** A stopped VM may still have Oracle Java on disk, so list stopped VMs in the audit as "not scanned (deallocated)". Scan them later only if their owners start them for their own reasons.

## 7. Cross-check, if you have Defender for Servers or Defender for Endpoint

Run this in Defender XDR Advanced Hunting:

```kusto
DeviceTvmSoftwareInventory
| where SoftwareName has_any ("jdk", "jre", "java", "openjdk", "corretto", "zulu", "temurin")
| summarize Versions = make_set(SoftwareVersion) by DeviceName, SoftwareVendor, SoftwareName
```

Defender won't list most **bundled** runtimes, which is the main reason for this script.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `No inventory data in output` | Check the VM agent is Ready, outbound 443 is open, and look in `C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.RunCommandWindows\*\RunCommandExtension.log` |
| `Conflict` or `another operation in progress` | Someone else is running a Run Command on that VM. Wait and run again for that VM only (`-VMName`) |
| `Completed (partial - time budget hit)` | Raise `-ScanTimeoutMinutes` (up to 80) or use `-SkipJarScan` |
| Errors about the `DefaultProfile` / context | Update Az (`Update-Module Az`). The script passes each subscription's context to its jobs |
| High `Access denied` count in ScanInfo | Normal for a few protected folders. A very high count means paths are too long or have unusual ACLs. Look at the folders by hand |
| Running it locally on one server without Azure | `.\Get-JavaInventory.ps1 -LocalCsvPath C:\temp\java.csv` (writes only that file) |
