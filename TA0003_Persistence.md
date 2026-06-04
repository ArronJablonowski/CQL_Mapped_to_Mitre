# TA0003 - Persistence

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Persistence. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1053.005]] - Scheduled Task

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect scheduled task creation or modification that launches script interpreters, LOLBAS utilities, or binaries from user-writable paths.
* Telemetry Requirements: ProcessRollup2, ScheduledTaskRegistered

#### Production-Ready CQL Query:

```cql
// Title: Suspicious Scheduled Task Creation
// Focus: schtasks.exe or PowerShell scheduled task registering suspicious action
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(schtasks|powershell|pwsh)\.exe$/i
| CommandLine=/((\/create|\/change|Register-ScheduledTask|New-ScheduledTaskAction).*(powershell|cmd|wscript|cscript|mshta|rundll32|\\Users\\|\\ProgramData\\|\\Temp\\))/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Task registration switches plus suspicious action path/interpreter.
* Triage Steps: Export task XML, validate author/action/trigger, and hunt for related [[T1059]] process execution.
* Potential False Positives: Software installers, endpoint management platforms, backup agents.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"schtasks.exe","CommandLine":"schtasks /create /tn UpdateSvc /sc minute /mo 30 /tr C:\\ProgramData\\updater.exe"}
```

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find events triggered on an event

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: events_triggered_by_event.yml
> cql_hub_name:: Find events triggered on an event
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`events_triggered_by_event.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.EventTrigger.Enabled)
| Trigger=*
| table([aid, Trigger, TaskXml], limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `events_triggered_by_event.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find hidden scheduled tasks

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: hidden_scheduled_tasks.yml
> cql_hub_name:: Find hidden scheduled tasks
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`hidden_scheduled_tasks.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Hidden:=rename(Task.Settings.Hidden)
| Hidden=/true/i
| table([aid,Hidden,TaskXml],limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `hidden_scheduled_tasks.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find events triggered at logon

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: logon_events.yml
> cql_hub_name:: Find events triggered at logon
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`logon_events.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.LogonTrigger.Enabled)
| Trigger=*
| table([aid, Trigger, TaskXml], limit=1000)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `logon_events.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find events that are scheduled

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: scheduled_events.yml
> cql_hub_name:: Find events that are scheduled
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`scheduled_events.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.CalendarTrigger.Enabled)
| Trigger=*
| table([aid, Trigger, TaskXml], limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `scheduled_events.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find events triggered at startup

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: startup_events.yml
> cql_hub_name:: Find events triggered at startup
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`startup_events.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.BootTrigger.Enabled)
| Trigger=*
| table([aid, Trigger, TaskXml], limit=1000)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `startup_events.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find tasks scheduled by logon type

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: task_scheduled_by_logon_type.yml
> cql_hub_name:: Find tasks scheduled by logon type
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`task_scheduled_by_logon_type.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| LogonType:=rename(Task.Principals.Principal.LogonType)
| LogonType=*
| table([aid, LogonType, TaskXml], limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `task_scheduled_by_logon_type.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find tasks scheduled by run level

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: tasks_scheduled_by_run_level.yml
> cql_hub_name:: Find tasks scheduled by run level
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`tasks_scheduled_by_run_level.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| RunLevel:=rename(Task.Principals.Principal.RunLevel)
| RunLevel=*
| table([aid, RunLevel, TaskXml], limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `tasks_scheduled_by_run_level.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find tasks scheduled by user ID

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: tasks_scheduled_by_user_ID.yml
> cql_hub_name:: Find tasks scheduled by user ID
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`tasks_scheduled_by_user_ID.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| UserId:=rename(Task.Principals.Principal.UserId)
| table([aid, UserId, TaskXml], limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `tasks_scheduled_by_user_ID.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find tasks scheduled with ComHandler

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: tasks_scheduled_with_ComHandler.yml
> cql_hub_name:: Find tasks scheduled with ComHandler
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`tasks_scheduled_with_ComHandler.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| ComHandlerData:=rename(Task.Actions.ComHandler.Data)
| ComHandlerData=*
| table([aid, ComHandlerData, TaskXml], limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `tasks_scheduled_with_ComHandler.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1053.005]] - Scheduled Task — CQL Hub: Find events triggered at a specific time

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1053.005
> technique_name:: Scheduled Task
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: time_events.yml
> cql_hub_name:: Find events triggered at a specific time
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1053.005
> related_mitre_ids:: T1053.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`time_events.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1053.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger := rename(Task.Triggers.TimeTrigger.Enabled)
| Trigger=*
| table([aid, Trigger, TaskXml], limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `time_events.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1547.001]] - Registry Run Keys / Startup Folder

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1547.001
> technique_name:: Registry Run Keys / Startup Folder
> logscale_stream:: RegistryValueSet
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect autorun registry value creation pointing to suspicious interpreters or user-writable payload locations.
* Telemetry Requirements: RegistryValueSet, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Run Key Persistence to Suspicious Path
// Focus: Registry Run/RunOnce values containing script utilities or non-standard executable paths
#event_simpleName=RegistryValueSet
| RegObjectName=/\\Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunServices|Policies\\Explorer\\Run)/i
| RegStringValue=/(powershell|wscript|cscript|mshta|rundll32|\\Users\\|\\ProgramData\\|\\Temp\\|\\AppData\\)/i
| select([@timestamp, ComputerName, aid, UserName, ImageFileName, RegObjectName, RegValueName, RegStringValue])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Autorun registry key and value data referencing suspicious execution paths or interpreters.
* Triage Steps: Review modifying process and user hive; disable value after preserving evidence if unauthorized.
* Potential False Positives: Legitimate updaters under ProgramData/AppData; allowlist signed vendor paths after validation.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"RegistryValueSet","RegObjectName":"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run","RegValueName":"Updater","RegStringValue":"C:\\Users\\Public\\updater.exe"}
```

---

### [[T1543.003]] - Windows Service

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1543.003
> technique_name:: Windows Service
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect service creation where the service binary references user-writable directories, command shells, or script hosts.
* Telemetry Requirements: ProcessRollup2, ServiceStarted, ServiceInstalled

#### Production-Ready CQL Query:

```cql
// Title: Suspicious Windows Service Installation
// Focus: sc.exe/New-Service creating service with unusual binary path
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(sc|powershell|pwsh)\.exe$/i
| CommandLine=/((create|New-Service).*(binPath|BinaryPathName).*(\\Users\\|\\ProgramData\\|\\Temp\\|cmd\.exe|powershell|wscript|rundll32))/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Service creation semantics plus suspicious service binary or interpreter.
* Triage Steps: Inspect service configuration, binary signer/hash, and start type; correlate to privilege escalation [[T1543.003]].
* Potential False Positives: IT deployment tools and legitimate service installers.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"sc.exe","CommandLine":"sc.exe create WinUpdate binPath= C:\\ProgramData\\winup.exe start= auto"}
```

---

### [[T1136]] - Create Account

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1136
> technique_name:: Create Account
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect local or domain account creation through net.exe or PowerShell, especially paired with local administrators group modification.
* Telemetry Requirements: ProcessRollup2, UserAccountCreated

#### Production-Ready CQL Query:

```cql
// Title: New Local or Domain Account Creation
// Focus: net user /add or New-LocalUser/New-ADUser
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(net|powershell|pwsh|dsadd)\.exe$/i
| CommandLine=/(net\s+user\s+.+\s+\/add|New-LocalUser|New-ADUser|dsadd\s+user)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Account creation verbs from command-line tools.
* Triage Steps: Verify creator, new account, group membership, and whether it was added to Administrators/RDP groups.
* Potential False Positives: Helpdesk provisioning and lab account creation.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"net.exe","CommandLine":"net user svc-backup P@ssw0rd! /add"}
```

---

### [[T1505.003]] - Web Shell

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1505.003
> technique_name:: Web Shell
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect web server processes writing script files or spawning shells, common webshell deployment/execution indicators.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Web Server Writing or Executing Webshell Content
// Focus: IIS/Apache/Tomcat process writes or runs script/shell content
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(w3wp|httpd|apache|tomcat|nginx|php-cgi|java)\.exe$/i
| ImageFileName=/\\(cmd|powershell|pwsh|cscript|wscript|certutil|curl|whoami)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Web worker parent and shell/utility child.
* Triage Steps: Capture webroot file modifications and web logs; hunt for newly written .aspx/.jsp/.php files.
* Potential False Positives: Legitimate application maintenance scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"w3wp.exe","FileName":"powershell.exe","CommandLine":"powershell -c whoami"}
```

---

### [[T1546.003]] - Windows Management Instrumentation Event Subscription

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1546.003
> technique_name:: Windows Management Instrumentation Event Subscription
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect creation of WMI permanent event subscriptions using PowerShell or wmic. This is a durable stealthy persistence mechanism.
* Telemetry Requirements: ProcessRollup2, WmiCreateFilter, WmiCreateConsumer

#### Production-Ready CQL Query:

```cql
// Title: WMI Permanent Event Subscription Creation
// Focus: __EventFilter / CommandLineEventConsumer / __FilterToConsumerBinding
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|wmic|mofcomp)\.exe$/i
| CommandLine=/(__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding|root\\subscription|mofcomp)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: WMI subscription class names and namespace references.
* Triage Steps: Enumerate root\subscription and remove unauthorized filters/consumers after evidence capture.
* Potential False Positives: Monitoring products and rare admin automation.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Set-WmiInstance -Namespace root\\subscription -Class __EventFilter"}
```

---

### [[T1546.008]] - Accessibility Features

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1546.008
> technique_name:: Accessibility Features
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect IFEO debugger or accessibility binary replacement patterns used for logon-screen persistence.
* Telemetry Requirements: ProcessRollup2, RegistryValueSet, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Accessibility Feature or IFEO Persistence
// Focus: sethc/utilman/oskscr debugger hijack or binary copy
#event_simpleName=ProcessRollup2
| CommandLine=/(Image File Execution Options|sethc\.exe|utilman\.exe|osk\.exe|magnify\.exe|narrator\.exe|Debugger|cmd\.exe)/i
| ImageFileName=/\\(reg|copy|cmd|powershell|pwsh)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Accessibility binary names, IFEO Debugger value, or cmd.exe replacement.
* Triage Steps: Inspect IFEO registry keys and system32 binary timestamps/hashes.
* Potential False Positives: Accessibility tooling configuration, forensic labs.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"reg.exe","CommandLine":"reg add HKLM\\...\\Image File Execution Options\\sethc.exe /v Debugger /d cmd.exe"}
```

---

### [[T1098]] - Account Manipulation

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1098
> technique_name:: Account Manipulation
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect commands adding users to privileged groups or modifying account settings for persistent access.
* Telemetry Requirements: ProcessRollup2, UserAccountModified

#### Production-Ready CQL Query:

```cql
// Title: Privileged Group Membership Modification
// Focus: net localgroup/Add-ADGroupMember/Add-LocalGroupMember
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(net|powershell|pwsh|dsmod)\.exe$/i
| CommandLine=/(net\s+localgroup\s+(administrators|remote desktop users).+\/add|Add-LocalGroupMember|Add-ADGroupMember|dsmod\s+group.+-addmbr)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Privileged group membership modification verbs.
* Triage Steps: Verify who initiated the change and whether the target account is authorized.
* Potential False Positives: Helpdesk/admin account management.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"net.exe","CommandLine":"net localgroup administrators backdoor /add"}
```

---

### [[T1098]] - Account Manipulation — CQL Hub: New API Keys within the Falcon Platform

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1098
> technique_name:: Account Manipulation
> logscale_stream:: Other
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: API_key_creation.yml
> cql_hub_name:: New API Keys within the Falcon Platform
> cql_hub_author:: ByteRay
> related_mitre_ids:: T1098
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: This query provides a list of newly created API Keys, including relevant details such as Client Name and Client ID.

* Telemetry Requirements: Other
* Source: CQL Hub (`API_key_creation.yml`), author: ByteRay.

#### Production-Ready CQL Query:

```cql
#event.dataset = falcon.cloud
| OperationName = CreateAPIClient
| user.id = *
| "Client Name" := rename(Attributes.name)
| "Client ID" := rename(Attributes.APIClientID)
| "Scope(s)" := rename("Attributes.scope(s)")
| table([timestamp,"Client Name","Client ID", "Scope(s)",OperationName,Success,Source,SourceIp,UserId])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `API_key_creation.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1098]] - Account Manipulation — CQL Hub: Created Local User Accounts

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1098
> technique_name:: Account Manipulation
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: created_local_user_accounts.yml
> cql_hub_name:: Created Local User Accounts
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1098
> related_mitre_ids:: T1098
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Table of all created local user accounts including UserName, ComputerName, aid, aip, and LocalIP.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`created_local_user_accounts.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1098.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=UserAccountCreated
| table([@timestamp, UserName, aid, aip, ComputerName, event_platform, LocalIP, name], limit=20000)
| sort(@timestamp)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `created_local_user_accounts.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1098]] - Account Manipulation — CQL Hub: Deleted Local User Accounts

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1098
> technique_name:: Account Manipulation
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: deleted_local_user_accounts.yml
> cql_hub_name:: Deleted Local User Accounts
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1098
> related_mitre_ids:: T1098
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Table of all deleted local user accounts including UserName, ComputerName, aid, aip, and LocalIP.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`deleted_local_user_accounts.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1098.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=UserAccountDeleted
| groupBy([UserName, aid, aip, ComputerName, event_platform, LocalIP, name], function=selectLast([@timestamp]))
| table([@timestamp, UserName, ComputerName, aid, aip, event_platform, LocalIP, name])
| sort(@timestamp)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `deleted_local_user_accounts.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1098]] - Account Manipulation — CQL Hub: Security Group Created (Microsoft Defender for Identity)

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1098
> technique_name:: Account Manipulation
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: security_group_created_microsoft_defender_for_identity.yml
> cql_hub_name:: Security Group Created (Microsoft Defender for Identity)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1098
> related_mitre_ids:: T1098
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: Detects the creation of a new security group in Active Directory as identified by Microsoft Defender for Identity. While often legitimate, this activity may indicate preparation for privilege escalation or unauthorized access management and should be reviewed.

* Telemetry Requirements: Identity
* Source: CQL Hub (`security_group_created_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1098.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor="microsoft"
| #event.dataset="defender-identity.IdentityDirectoryEvents"
| event.action = "security group created"
| #event.outcome = success
| table([@timestamp,Vendor.properties.AdditionalFields.TARGET_OBJECT.GROUP,Vendor.properties.DestinationDeviceName])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects the creation of a new security group in Active Directory as identified by Microsoft Defender for Identity. While often legitimate, this activity may indicate preparation for privilege escalation or unauthorized access management and should be reviewed.
* Key Indicators: Review query output fields and filters from `security_group_created_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1547.004]] - Winlogon Helper DLL

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1547.004
> technique_name:: Winlogon Helper DLL
> logscale_stream:: RegistryValueSet
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect modifications to Winlogon Shell, Userinit, Notify, or helper DLL values used for logon persistence.
* Telemetry Requirements: RegistryValueSet, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Winlogon Persistence Registry Modification
// Focus: Winlogon Shell/Userinit/Notify changes
#event_simpleName=RegistryValueSet
| RegObjectName=/\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/i
| RegValueName=/^(Shell|Userinit|Notify|Taskman|VmApplet)$/i
| NOT RegStringValue=/explorer\.exe|userinit\.exe/i
| select([@timestamp, ComputerName, aid, UserName, ImageFileName, RegObjectName, RegValueName, RegStringValue])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Winlogon autorun values changed away from defaults.
* Triage Steps: Compare to baseline, inspect modifying process, and check referenced binary.
* Potential False Positives: Rare legitimate shell replacement/kiosk systems.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"RegistryValueSet","RegObjectName":"HKLM\\...\\Winlogon","RegValueName":"Shell","RegStringValue":"explorer.exe, C:\\ProgramData\\svc.exe"}
```

---

### [[T1547.009]] - Shortcut Modification

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1547.009
> technique_name:: Shortcut Modification
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Persistence

* Detection Objective: Detect creation or modification of LNK files to launch scripts or payloads from startup or user directories.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Startup Shortcut Persistence
// Focus: LNK creation in Startup paths pointing to script or LOLBAS content
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|cmd|wscript|cscript)\.exe$/i
| CommandLine=/(\.lnk|Startup|WScript\.Shell|CreateShortcut).*(powershell|wscript|mshta|rundll32|\\ProgramData\\|\\Users\\Public\\|\\Temp\\)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Shortcut creation APIs, Startup path, and suspicious target interpreter/path.
* Triage Steps: Inspect shortcut target and creator; review user Startup folder contents.
* Potential False Positives: Installer-created shortcuts; tune known software.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"CreateShortcut to Startup updater.lnk"}
```

---

### [[T1546]] - Event Triggered Execution — CQL Hub: Detect Critical Environment Variable Changes over SSH with Connection Details

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1546
> technique_name:: Event Triggered Execution
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Detect_Critical_Environment_Variable_Changes_over_SSH_with_Connection_Details.yml
> cql_hub_name:: Detect Critical Environment Variable Changes over SSH with Connection Details
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: TA0003
> related_mitre_ids:: T1546
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: The query identifies critical changes to critical environment variables, extracts connection details such as user, local and remote IPs and ports, and provides a direct link to the related process in Falcon Process Explorer.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Detect_Critical_Environment_Variable_Changes_over_SSH_with_Connection_Details.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: TA0003.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=CriticalEnvironmentVariableChanged
| EnvironmentVariableName =/(SSH_CONNECTION|USER)/
| EnvironmentVariableValue=/(?<localIP>\d+\.\d+\.\d+\.\d+)\s+(?<localPort>\d+)\s+(?<remoteIP>\d+\.\d+\.\d+\.\d+)\s+(?<remotePort>\d+)$/i
| table([@timestamp, aid, userName, remoteIP, remotePort, localIP, localPort])
| "Process Explorer" := format("[Process Explorer](https://falcon.crowdstrike.com/investigate/process-explorer/%s/%s)", field=["aid", "ContextProcessId"])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Critical%20Environment%20Variable%20Changed%20SSH.md)
* Key Indicators: Review query output fields and filters from `Detect_Critical_Environment_Variable_Changes_over_SSH_with_Connection_Details.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1176]] - Software Extensions — CQL Hub: Inventory of Installed Browser Extensions Across Endpoints

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1176
> technique_name:: Software Extensions
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Installed_Browser_Extensions_Across_Endpoints.yml
> cql_hub_name:: Inventory of Installed Browser Extensions Across Endpoints
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1176
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: The query lists installed browser (Chrome & Edge) extensions across endpoints, normalizes browser names, counts unique systems per extension, adds a Chrome Web Store link, and sorts results to highlight the most common extensions.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Installed_Browser_Extensions_Across_Endpoints.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
| groupBy([event_platform, BrowserName, BrowserExtensionId, BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))
| format("[See Extension](https://chromewebstore.google.com/detail/%s)", field=[BrowserExtensionId], as="Chrome Store Link")
| sort(order=desc, TotalEndpoints, limit=1000)
| case{
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    *;
}

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Enumerate%20Chrome%20%2B%20Edge%20Browser%20Extension%20on%20Win%20and%20Mac.md)
* Key Indicators: Review query output fields and filters from `Installed_Browser_Extensions_Across_Endpoints.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1176]] - Software Extensions — CQL Hub: Installed Browser Extensions (Aggregate by Extension)

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1176
> technique_name:: Software Extensions
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: installed_browser_extensions__aggregate_by_extension_.yml
> cql_hub_name:: Installed Browser Extensions (Aggregate by Extension)
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1176
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: This query will output a table with all installed browser extensions.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`installed_browser_extensions__aggregate_by_extension_.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get browser extension event
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"

// Aggregate by event_platform, BrowserName, ExtensionID and ExtensionName
| groupBy([event_platform, BrowserName, BrowserExtensionId, BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))

// Check to see if the extension is installed on fewer than 50 systems
| test(TotalEndpoints<50)

// Create a link to the Chrome Extension Store
| format("[See Extension](https://chromewebstore.google.com/detail/%s)", field=[BrowserExtensionId], as="Chrome Store Link")

// Sort in descending order
| sort(order=desc, TotalEndpoints, limit=1000)

// Convert the browser name from decimal to human-readable
| case{
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    *;
}
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `installed_browser_extensions__aggregate_by_extension_.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1176]] - Software Extensions — CQL Hub: Installed Browser Extensions (Hunt Extension Name)

> [!metadata]+ Detection Metadata
> tactic:: Persistence
> technique_id:: T1176
> technique_name:: Software Extensions
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: installed_browser_extensions__hunt_extension_name_.yml
> cql_hub_name:: Installed Browser Extensions (Hunt Extension Name)
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1176
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Persistence, CQL_Hub

* Detection Objective: This query will output a table with all installed browser extensions.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`installed_browser_extensions__hunt_extension_name_.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get browser extension event
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"

// Look for string "vpn" in extension name
| BrowserExtensionName=/vpn/i

// Make a new field that includes the extension ID and Name
| Extension:=format(format="%s (%s)", field=[BrowserExtensionId, BrowserExtensionName])

// Aggregate by endpoint and browser profile
| groupBy([event_platform, aid, ComputerName, UserName, BrowserProfileId, BrowserName], function=([collect([Extension])]))

// Get unnecessary field
| drop([_count])

// Convert browser name from decimal to human readable
| case{
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    *;
}

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Replace "vpn" with the string you want to hunt for.
* Key Indicators: Review query output fields and filters from `installed_browser_extensions__hunt_extension_name_.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
