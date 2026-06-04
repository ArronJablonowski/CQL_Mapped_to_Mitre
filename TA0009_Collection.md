# TA0009 - Collection

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Collection. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1005]] - Data from Local System

> [!metadata]+ Detection Metadata
> tactic:: Collection
> technique_id:: T1005
> technique_name:: Data from Local System
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Collection

* Detection Objective: Detect command-line collection of sensitive local files or directories into staging paths.
* Telemetry Requirements: ProcessRollup2, FileOpenInfo

#### Production-Ready CQL Query:

```cql
// Title: Sensitive Local File Collection to Staging Path
// Focus: copy/robocopy/PowerShell targeting Documents/Desktop with archive or staging output
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|cmd|robocopy|xcopy|tar|7z|rar|winrar)\.exe$/i
| CommandLine=/(Documents|Desktop|Downloads|OneDrive|SharePoint).*(\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\.zip|\.7z|\.rar|\.tar)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Sensitive user folders referenced with staging/archive destinations.
* Triage Steps: Determine exact files staged, user context, and whether outbound transfer occurred.
* Potential False Positives: User backups, migration tools, compression utilities.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Compress-Archive C:\\Users\\alice\\Documents C:\\Users\\Public\\docs.zip"}
```

---

### [[T1113]] - Screen Capture

> [!metadata]+ Detection Metadata
> tactic:: Collection
> technique_id:: T1113
> technique_name:: Screen Capture
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Collection

* Detection Objective: Detect built-in or scripted screen capture utilities run by shells or unusual parents.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Scripted Screenshot Capture
// Focus: PowerShell/.NET screen capture and screenshot tool execution
#event_simpleName=ProcessRollup2
| CommandLine=/(CopyFromScreen|System\.Drawing|Graphics|screenshot|screen capture|nircmd.+savescreenshot|SnippingTool|psr\.exe)/i
| ImageFileName=/\\(powershell|pwsh|cmd|nircmd|psr|snippingtool)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Screenshot APIs or tools launched from command line.
* Triage Steps: Review parent process and output files; check if activity aligns to user support session.
* Potential False Positives: Helpdesk support, QA automation, user-initiated screenshot tools.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Add-Type -AssemblyName System.Drawing; CopyFromScreen"}
```

---

### [[T1560]] - Archive Collected Data

> [!metadata]+ Detection Metadata
> tactic:: Collection
> technique_id:: T1560
> technique_name:: Archive Collected Data
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Collection

* Detection Objective: Detect archive utilities compressing sensitive user or business directories into staging locations.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Sensitive Data Archiving to Staging Directory
// Focus: 7z/rar/tar/Compress-Archive against Documents/Desktop/shares
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(7z|rar|winrar|tar|powershell|pwsh)\.exe$/i
| CommandLine=/( a |Compress-Archive| -czf | -cf ).*(Documents|Desktop|Downloads|\\\\[^\\]+\\|OneDrive|SharePoint).*(\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\.zip|\.7z|\.rar|\.tar)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Archive command and sensitive source directory with staging destination.
* Triage Steps: Review archived paths and whether transfer followed.
* Potential False Positives: User backups and legitimate compression.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"7z.exe","CommandLine":"7z a C:\\Users\\Public\\hr.7z C:\\Shares\\HR"}
```

---

### [[T1119]] - Automated Collection

> [!metadata]+ Detection Metadata
> tactic:: Collection
> technique_id:: T1119
> technique_name:: Automated Collection
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Collection

* Detection Objective: Detect scripted recursive collection over common document extensions.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Recursive Document Collection Script
// Focus: PowerShell/cmd recursive copy/search for documents
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|cmd|robocopy|xcopy)\.exe$/i
| CommandLine=/(Get-ChildItem|dir\s+\/s|robocopy|xcopy).*(\.docx|\.xlsx|\.pdf|\.pst|\.csv|\.txt|Documents|Desktop)/i
| CommandLine=/(\\Users\\Public\\|\\ProgramData\\|\\Temp\\|archive|collect|staging)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Recursive collection commands with business-file extensions.
* Triage Steps: Identify collected file set and staging directory; correlate with archive/exfiltration.
* Potential False Positives: Migration scripts and backup jobs.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Get-ChildItem C:\\Users -Recurse -Include *.docx,*.xlsx | copy C:\\Users\\Public\\collect"}
```

---

### [[T1115]] - Clipboard Data

> [!metadata]+ Detection Metadata
> tactic:: Collection
> technique_id:: T1115
> technique_name:: Clipboard Data
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Collection

* Detection Objective: Detect command-line or script access to clipboard contents.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Clipboard Capture via Script
// Focus: Get-Clipboard/pbpaste/clipboard API tokens
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|cmd|python)\.exe$/i
| CommandLine=/(Get-Clipboard|Set-Clipboard|Clipboard|System\.Windows\.Forms|pyperclip|GetText\(\))/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Clipboard cmdlets/API tokens.
* Triage Steps: Inspect parent process and destination file/network activity.
* Potential False Positives: User productivity scripts and clipboard managers.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Get-Clipboard > C:\\Users\\Public\\clip.txt"}
```

---

### [[T1213]] - Data from Information Repositories

> [!metadata]+ Detection Metadata
> tactic:: Collection
> technique_id:: T1213
> technique_name:: Data from Information Repositories
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Collection

* Detection Objective: Detect CLI collection from SharePoint, Confluence, Git, cloud drives, or file repositories.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Repository Data Collection via CLI
// Focus: git/gh/rclone/curl/wget against repositories and knowledge bases
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(git|gh|rclone|curl|wget|powershell|pwsh)\.exe$/i
| CommandLine=/(clone|pull|download|export|sync).*(sharepoint|confluence|atlassian|github|gitlab|bitbucket|onedrive|drive|wiki|repo)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Repository/cloud source names with bulk collection verbs.
* Triage Steps: Determine repo/site and volume; validate user authorization and destination.
* Potential False Positives: Developer/admin repository operations.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"git.exe","CommandLine":"git clone https://gitlab.example.com/security/secrets.git"}
```
