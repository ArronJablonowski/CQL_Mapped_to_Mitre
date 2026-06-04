# TA0040 - Impact

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Impact. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1486]] - Data Encrypted for Impact

> [!metadata]+ Detection Metadata
> tactic:: Impact
> technique_id:: T1486
> technique_name:: Data Encrypted for Impact
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Impact

* Detection Objective: Detect ransomware-like mass encryption helpers or commands disabling recovery before file encryption.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Ransomware Pre-Encryption and Encryption Utility Signals
// Focus: vssadmin/wbadmin/bcdedit plus archive/encryption commands
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(vssadmin|wbadmin|bcdedit|cipher|powershell|cmd|7z|rar)\.exe$/i
| CommandLine=/(delete\s+shadows|resize\s+shadowstorage|delete\s+catalog|recoveryenabled\s+No|bootstatuspolicy\s+ignoreallfailures|cipher\s+\/w|\.locked|\.encrypted|password| -p)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Shadow copy deletion, recovery disablement, or encryption/archive password operations.
* Triage Steps: Escalate immediately; isolate host and check for file rename/write burst telemetry.
* Potential False Positives: Backup maintenance for vssadmin/wbadmin; legitimate encrypted archives.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"vssadmin.exe","CommandLine":"vssadmin delete shadows /all /quiet"}
```

---

### [[T1490]] - Inhibit System Recovery

> [!metadata]+ Detection Metadata
> tactic:: Impact
> technique_id:: T1490
> technique_name:: Inhibit System Recovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Impact

* Detection Objective: Detect commands that remove backup catalogs, delete shadow copies, or disable boot recovery.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: System Recovery Inhibition Commands
// Focus: vssadmin/wbadmin/bcdedit/reagentc recovery destruction
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(vssadmin|wmic|wbadmin|bcdedit|reagentc|powershell|pwsh)\.exe$/i
| CommandLine=/(shadowcopy\s+delete|delete\s+shadows|delete\s+catalog|recoveryenabled\s+No|bootstatuspolicy\s+ignoreallfailures|reagentc\s+\/disable|Checkpoint-Computer|Get-ComputerRestorePoint)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Direct manipulation of recovery and backup mechanisms.
* Triage Steps: Check whether command was authorized backup maintenance; otherwise isolate and begin ransomware containment.
* Potential False Positives: Planned backup rotations, disaster recovery tests.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"bcdedit.exe","CommandLine":"bcdedit /set {default} recoveryenabled No"}
```

---

### [[T1489]] - Service Stop

> [!metadata]+ Detection Metadata
> tactic:: Impact
> technique_id:: T1489
> technique_name:: Service Stop
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Impact

* Detection Objective: Detect bulk or targeted stopping of security, backup, database, or mail services prior to impact actions.
* Telemetry Requirements: ProcessRollup2, ServiceStopped

#### Production-Ready CQL Query:

```cql
// Title: Critical Service Stop via Native Tools
// Focus: net/sc/taskkill stopping security or backup services
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(net|sc|taskkill|powershell|pwsh)\.exe$/i
| CommandLine=/((stop|Stop-Service|taskkill).*(WinDefend|Sense|backup|veeam|sql|mssql|exchange|oracle|postgres|crowdstrike|falcon|csagent|carbonblack|sentinel))/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Service termination commands aimed at security, backup, or data services.
* Triage Steps: Validate admin change window; if unauthorized, isolate and check for subsequent encryption or deletion.
* Potential False Positives: Patch windows, backup maintenance, database administration.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"net.exe","CommandLine":"net stop veeam"}
```

---

### [[T1485]] - Data Destruction

> [!metadata]+ Detection Metadata
> tactic:: Impact
> technique_id:: T1485
> technique_name:: Data Destruction
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Impact

* Detection Objective: Detect destructive file deletion or wiping commands over broad paths.
* Telemetry Requirements: ProcessRollup2, FileDeleted

#### Production-Ready CQL Query:

```cql
// Title: Broad Data Destruction Command
// Focus: recursive force deletion/wipe of user, share, or application directories
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(cmd|powershell|pwsh|del|erase|sdelete|cipher|rm)\.exe$/i
| CommandLine=/(del\s+\/s\s+\/q|Remove-Item.+-Recurse.+-Force|sdelete|cipher\s+\/w|rm\s+-rf).*(\\Users\\|\\Shares\\|\\ProgramData\\|\\inetpub\\|\\MSSQL|\\Backups)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Recursive forced deletion or wiping of high-value paths.
* Triage Steps: Escalate immediately; isolate host and preserve process/file deletion telemetry.
* Potential False Positives: Admin cleanup scripts; should be scoped and change-controlled.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Remove-Item C:\\Shares\\Finance -Recurse -Force"}
```

---

### [[T1531]] - Account Access Removal

> [!metadata]+ Detection Metadata
> tactic:: Impact
> technique_id:: T1531
> technique_name:: Account Access Removal
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Impact

* Detection Objective: Detect commands disabling accounts or changing passwords in bulk, which can be used for impact and lockout.
* Telemetry Requirements: ProcessRollup2, UserAccountModified

#### Production-Ready CQL Query:

```cql
// Title: Account Disablement or Password Reset Burst
// Focus: net user /active:no, Disable-ADAccount, Set-ADAccountPassword
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(net|powershell|pwsh|dsmod)\.exe$/i
| CommandLine=/(net\s+user.+\/active:no|Disable-ADAccount|Set-ADAccountPassword|dsmod\s+user.+-disabled yes|Search-ADAccount.+-LockedOut)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Account disable/password reset command verbs.
* Triage Steps: Validate change window and identity admin context; check for broad scope or automation.
* Potential False Positives: Legitimate account lifecycle operations.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Disable-ADAccount -Identity jsmith"}
```

---

### [[T1565.001]] - Stored Data Manipulation

> [!metadata]+ Detection Metadata
> tactic:: Impact
> technique_id:: T1565.001
> technique_name:: Stored Data Manipulation
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Impact

* Detection Objective: Detect command-line bulk modification of business data stores or scripts used to alter records.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Bulk Stored Data Manipulation
// Focus: sqlcmd/mysql/psql/PowerShell update/delete operations against data stores
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(sqlcmd|mysql|psql|powershell|pwsh|python)\.exe$/i
| CommandLine=/(UPDATE\s+|DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|Invoke-Sqlcmd|bulk|overwrite|Set-Content).*(where|from|database|\.csv|\.json)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Bulk data manipulation verbs from command line.
* Triage Steps: Validate DBA/change context and identify affected data set.
* Potential False Positives: Database administration and ETL jobs.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"sqlcmd.exe","CommandLine":"sqlcmd -Q \"DELETE FROM Orders WHERE date < getdate()\""}
```

---

### [[T1491.001]] - Internal Defacement

> [!metadata]+ Detection Metadata
> tactic:: Impact
> technique_id:: T1491.001
> technique_name:: Internal Defacement
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Impact

* Detection Objective: Detect modification of web content or desktop/login artifacts with defacement-themed filenames or commands.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Internal Web or Desktop Defacement
// Focus: webroot/default page overwrite or wallpaper/logon text modification
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(cmd|powershell|pwsh|copy|xcopy|reg)\.exe$/i
| CommandLine=/(index\.html|default\.aspx|iisstart\.htm|wallpaper|LegalNoticeText|LegalNoticeCaption|deface|hacked|owned)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Webroot/default page or logon/wallpaper modification tokens.
* Triage Steps: Inspect modified content and webroot; determine scope across hosts.
* Potential False Positives: Legitimate website deployments and branding changes.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"copy.exe","CommandLine":"copy owned.html C:\\inetpub\\wwwroot\\index.html"}
```

---

### [[T1499]] - Endpoint Denial of Service

> [!metadata]+ Detection Metadata
> tactic:: Impact
> technique_id:: T1499
> technique_name:: Endpoint Denial of Service
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Impact

* Detection Objective: Detect commands that intentionally exhaust CPU, memory, disk, or kill critical processes.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Endpoint Resource Exhaustion or Process Kill
// Focus: fork/bomb style commands, disk fill, or mass taskkill
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(cmd|powershell|pwsh|taskkill|fsutil|dd)\.exe$/i
| CommandLine=/(taskkill\s+\/f\s+\/im\s+\*|fsutil\s+file\s+createnew|while\s*\(\$true\)|Start-Job.*while|%0\|%0|dd\s+if=\/dev\/zero)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Resource exhaustion or mass process termination command patterns.
* Triage Steps: Escalate if unauthorized; isolate and review parent/persistence.
* Potential False Positives: Stress testing and admin diagnostics.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"fsutil.exe","CommandLine":"fsutil file createnew C:\bigfile.bin 100000000000"}
```
