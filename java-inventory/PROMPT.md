# Prompt: Java inventory for Azure Windows VMs (DevApp and Non-Prod)

> Use this to explain, rebuild or extend the tool. To scan, always use the committed scripts. A regenerated version will differ, and audit results must come from one consistent codebase.

---

## GOAL

Build a PowerShell tool that finds **every trace of Java** on my Azure Windows Server 2019 VMs:
- Oracle and non-Oracle JDKs and JREs
- Java runtimes bundled inside other software
- software that ships JAR files
- leftover traces from uninstalled Java

It has two purposes:
1. **Oracle Java licensing audit.** Tell Oracle JDK apart from free OpenJDK builds, with the exact version and an Oracle licence risk rating for each finding.
2. **A complete Java inventory**, for clean-up and visibility.

## CONTEXT

- **Environments:** two, **DevApp** and **Non-Prod**, each in its **own Azure subscription**. They must be scanned with **separate scripts** that produce **separate reports**.
- **Operating system:** Windows Server 2019 on every target. Windows PowerShell 5.1 is the default on the VMs, so the on-VM code must run on 5.1. The orchestrator must run on PowerShell 5.1 or 7.x.
- **Access:** I have **Virtual Machine Contributor** in both subscriptions. There must be no WinRM, RDP or open inbound ports.
- **Execution method:** **Azure Run Command** (`Invoke-AzVMRunCommand`, `RunPowerShellScript`). It runs as SYSTEM.
  - Run Command output is limited to the **last 4,096 bytes**. Design around this; never let results be cut off silently.
  - One Run Command can run per VM at a time, with a 90-minute maximum.
- **Hard rules:**
  - The scan is **read-only**. Never execute any `java.exe` that is found: read the vendor and version from file metadata and the `release` file.
  - **Leave each VM exactly as it was before the run:**
    - delete every temporary file the tool creates
    - delete the downloaded copies of the scripts
    - remove the Run Command extension (`Microsoft.CPlat.Core.RunCommandWindows`) **only if it was not installed before the run**
    - never load unloaded user hives, never compile code (no `Add-Type`), never touch audit or event logs
  - **Mask secrets** (password, pwd, secret, token, key, credential values) in any captured command line.
  - If anything raises a security concern, **stop and tell me** before continuing.
- **Scan depth:** a full scan: registry and a disk scan of every fixed drive, with a time budget so it finishes within the Run Command limit.

## ACTION

1. **Before writing code**, challenge my assumptions and ask about anything unclear: goal, context, action, output.
2. **On-VM collector (`Get-JavaInventory.ps1`).** Detect:
   - `java.exe`, `javaw.exe` and `jvm.dll` on all fixed drives. Skip reparse points and system folders. Resolve each to its Java home, folding a JDK 8 `jre\` folder into the JDK.
   - JAR files outside Java homes, grouped by application folder, including any log4j-core versions.
   - Vendor registry keys: JavaSoft, Adoptium, Azul, Corretto, Microsoft JDK, IBM, BellSoft, SapMachine. Report keys that point to missing folders as leftover traces.
   - Add/Remove Programs entries (64-bit, 32-bit and loaded user hives).
   - `JAVA_HOME`, `JRE_HOME`, `JDK_HOME` and `PATH` (machine and user).
   - Running `java.exe` processes, plus any process that has `jvm.dll` loaded.
   - Services that reference Java, and Apache Procrun (Tomcat) JVM settings.
   - Launcher stubs, e.g. `javapath` or `System32\java.exe`.

   For each Java home, record:
   - vendor
   - version (major and update)
   - JDK or JRE
   - Bundled or standalone
   - owning application (from the Add/Remove Programs install location, falling back to the application folder)
   - Oracle licence risk

   Always emit one ScanInfo row, so a server with no Java still proves it was scanned.
3. **Oracle licence rules.** Keep them in one editable function, rated High, Review or Low, and label them as triage only, not legal advice:
   - Low: 8u202 and earlier (BCL), 7u80 and earlier, 6u45 and earlier, 9 and 10
   - High: 8u211 and later (OTN), 11 to 16 (OTN), 17.0.13 and later (OTN)
   - Low: 17.0.0 to 17.0.12 (NFTC)
   - 21: NFTC, but flag the 2026 boundary for verification
   - Low: other non-LTS versions and 25 and later (NFTC)
   - Review: Oracle JDK inside an Oracle product (restricted use)
   - Review: GraalVM
   - Low: Oracle-built OpenJDK (GPL)
4. **Orchestrator (`Invoke-JavaInventory.ps1`):**
   - Find Windows VMs by subscription, resource group, tag or name. Skip stopped and non-Windows VMs, and report them as Skipped.
   - Record whether the Run Command extension already exists on each VM. Save that state to JSON.
   - Run the collector in parallel with a throttle. Results come back gzip-compressed and base64-encoded, in chunks of about 3,000 characters; fetch any extra chunks with follow-up Run Commands.
   - Then run cleanup, and remove the extension if this run installed it.
   - Provide `-ListOnly` (dry run), `-CleanupOnly -StateFile` (recover after an interrupted run), `-SkipJarScan`, `-KeepRunCommandExtension` and `-EnvironmentLabel`.
5. **Two environment launchers:** `Run-DevApp-Inventory.ps1` and `Run-NonProd-Inventory.ps1`. They are thin wrappers around **one shared engine**, never duplicated logic. Each has a SETTINGS block with `<FILL-ME>` placeholders, so real subscription IDs are never in chat or Git.

   A shared safety script must:
   - refuse to run while placeholders remain
   - validate the GUID format and that my account can see the subscription
   - warn when a subscription name looks like production, and in that case forbid skipping the confirmation
   - show the scope and signed-in account, then require typing `DevApp` or `NonProd` to confirm
6. **Verification:**
   - Say clearly what you couldn't test. Never claim untested code works.
   - Recommend this order: `-ListOnly`, then a single-VM pilot, then a full run.
   - Remind me to check that my RBAC scope is the subscription, not a resource group (otherwise some VMs are missed silently).
   - Remind me to activate any PIM role for longer than the whole run.
   - Remind me to compare the VM count with the Azure portal.
7. Commit the work to the repo with a README covering:
   - prerequisites
   - run steps
   - what changes on the VM and what deliberately stays (Azure/Windows audit logs)
   - the licence rule table
   - a Defender `DeviceTvmSoftwareInventory` KQL cross-check
   - troubleshooting

## OUTPUT

Per environment, write a separate folder `JavaInventory_<DevApp|NonProd>_<timestamp>\` containing:

| File | Content |
|---|---|
| `JavaInventory_Findings.csv` | One row per finding. Columns: Environment, VMName, ComputerName, FindingType, Vendor, Version, MajorVersion, UpdateVersion, JavaType, Bundled, OwningApplication, Path, IsOracle, OracleLicenseRisk, LicenseNote, Source, Details, ResourceGroup, Subscription, ScanTime |
| `JavaInventory_Oracle.csv` | Oracle-related rows only, for the licensing team |
| `JavaInventory_ServerStatus.csv` | One row per VM: Completed, Failed or Skipped, plus TempFilesCleaned and ExtensionRemoved |
| `JavaInventory_Summary.html` | A standalone page (no external dependencies) that works in light and dark mode. It has: summary cards; Oracle findings with High first; a vendor × version pivot; bundled-runtime and JAR-bundle tables; other traces; per-server cleanup status; failed and skipped servers; and the licensing caveat |
| `JavaInventory_State.json` | The pre-run extension state, for `-CleanupOnly` |

The inventory counts as **complete only when Failed = 0 and Skipped = 0**.

**Response style:**
- Challenge my assumptions first and lead with the uncomfortable truth.
- Tag claims [Certain], [Likely] or [Guessing].
- Disagree with reasons and give an alternative.
- Don't fold under pushback unless I give new information.
