# TA0004 - Privilege Escalation

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Privilege Escalation. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1548]] - Abuse Elevation Control Mechanism

> [!metadata]+ Detection Metadata
> tactic:: Privilege Escalation
> technique_id:: T1548
> technique_name:: Abuse Elevation Control Mechanism
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Privilege_Escalation

* Detection Objective: Detect UAC bypass and elevation-related LOLBAS patterns involving fodhelper, computerdefaults, sdclt, or registry handler hijack commands.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: UAC Bypass Helper Execution with Registry Hijack Context
// Focus: Known auto-elevating binaries and registry hijack setup
#event_simpleName=ProcessRollup2
| (ImageFileName=/\\(fodhelper|computerdefaults|sdclt|eventvwr)\.exe$/i OR CommandLine=/(\\Software\\Classes\\ms-settings\\Shell\\Open\\command|DelegateExecute|CurVer)/i)
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, IntegrityLevel])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Auto-elevating helper execution or registry keys used by common UAC bypasses.
* Triage Steps: Review nearby RegistryValueSet events and integrity transition; inspect parent process and user privileges.
* Potential False Positives: Legitimate control panel settings usage; suspicious when paired with registry edits and script parent.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"fodhelper.exe","ParentBaseFileName":"powershell.exe","IntegrityLevel":"High"}
```

---

### [[T1068]] - Exploitation for Privilege Escalation

> [!metadata]+ Detection Metadata
> tactic:: Privilege Escalation
> technique_id:: T1068
> technique_name:: Exploitation for Privilege Escalation
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Privilege_Escalation

* Detection Objective: Detect exploit-like process patterns where low-reputation binaries or scripts execute privilege inspection followed by service/control actions.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Exploit Staging Followed by Privilege Validation
// Focus: whoami /priv and service control from unusual parent/path
#event_simpleName=ProcessRollup2
| CommandLine=/(whoami\s+\/priv|SeImpersonatePrivilege|SeDebugPrivilege|PrintSpoofer|JuicyPotato|RoguePotato|SweetPotato|spoolss|EfsRpc)/i
| ImageFileName=/\\(cmd|powershell|whoami|printspoofer|juicypotato|roguepotato)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, IntegrityLevel])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Privilege exploit tool names, token privilege checks, or named pipe/RPC exploit strings.
* Triage Steps: Confirm binary provenance and whether a service account or web worker spawned the activity.
* Potential False Positives: Security testing tools and red-team exercises.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"whoami.exe","CommandLine":"whoami /priv","ParentBaseFileName":"cmd.exe"}
```

---

### [[T1134]] - Access Token Manipulation

> [!metadata]+ Detection Metadata
> tactic:: Privilege Escalation
> technique_id:: T1134
> technique_name:: Access Token Manipulation
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Privilege_Escalation

* Detection Objective: Detect token manipulation tooling or commands that enumerate/abuse privileges for impersonation.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Token Impersonation Tooling
// Focus: Incognito/printspoofer/mimikatz token commands and SeImpersonate checks
#event_simpleName=ProcessRollup2
| CommandLine=/(SeImpersonatePrivilege|SeAssignPrimaryToken|incognito|steal_token|make_token|token::|PrintSpoofer|GodPotato|JuicyPotato|RoguePotato)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, IntegrityLevel])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Token privilege names and known impersonation tool command tokens.
* Triage Steps: Validate service account context and parent process; inspect for spawned high-integrity shells.
* Potential False Positives: Red-team tools and privilege-audit scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"PrintSpoofer.exe","CommandLine":"PrintSpoofer.exe -i -c cmd"}
```

---

### [[T1055]] - Process Injection

> [!metadata]+ Detection Metadata
> tactic:: Privilege Escalation
> technique_id:: T1055
> technique_name:: Process Injection
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Privilege_Escalation

* Detection Objective: Detect common process-injection tooling terms and suspicious memory API usage surfaced in command-line or tool names.
* Telemetry Requirements: ProcessRollup2, ImageLoad

#### Production-Ready CQL Query:

```cql
// Title: Process Injection Tooling or API Invocation
// Focus: CreateRemoteThread/VirtualAlloc/reflective injection markers
#event_simpleName=ProcessRollup2
| CommandLine=/(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|QueueUserAPC|NtMapViewOfSection|reflective|inject|shellcode|process hollow|RunPE)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Injection API names and tool terminology.
* Triage Steps: Validate binary provenance and target process; inspect memory detections if available.
* Potential False Positives: Security tools, debuggers, EDR testing.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"injector.exe","CommandLine":"injector.exe --pid 444 --method CreateRemoteThread"}
```

---

### [[T1548.002]] - Bypass User Account Control

> [!metadata]+ Detection Metadata
> tactic:: Privilege Escalation
> technique_id:: T1548.002
> technique_name:: Bypass User Account Control
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Privilege_Escalation

* Detection Objective: Detect concrete UAC bypass registry hijacks and auto-elevating binary launch patterns.
* Telemetry Requirements: ProcessRollup2, RegistryValueSet

#### Production-Ready CQL Query:

```cql
// Title: UAC Bypass Registry Hijack and Auto-Elevate Launch
// Focus: ms-settings/fodhelper/computerdefaults eventvwr bypass patterns
#event_simpleName=ProcessRollup2
| CommandLine=/(ms-settings\\Shell\\Open\\command|DelegateExecute|fodhelper\.exe|computerdefaults\.exe|eventvwr\.exe|sdclt\.exe)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, IntegrityLevel])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: UAC bypass registry path or known auto-elevating helper.
* Triage Steps: Look for preceding RegistryValueSet and high-integrity child process.
* Potential False Positives: Legitimate settings control panel activity without registry hijack context.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"fodhelper.exe","ParentBaseFileName":"cmd.exe","IntegrityLevel":"High"}
```

---
