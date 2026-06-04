# TA0007 - Discovery

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Discovery. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1087.002]] - Domain Account

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1087.002
> technique_name:: Domain Account
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect domain account and privileged group enumeration using native Windows commands.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Domain Account and Group Enumeration
// Focus: net/nltest/dsquery PowerShell AD cmdlets
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(net|nltest|dsquery|powershell|pwsh)\.exe$/i
| CommandLine=/(net\s+(user|group|localgroup).+\/domain|domain admins|enterprise admins|nltest\s+\/dclist|Get-AD(User|Group|Computer)|dsquery\s+(user|group|computer))/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Domain enumeration commands and privileged group keywords.
* Triage Steps: Assess whether the user normally performs AD administration; pivot to preceding Initial Access and following Lateral Movement.
* Potential False Positives: Domain admins, identity engineering scripts, asset inventory.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"net.exe","CommandLine":"net group \"domain admins\" /domain"}
```

---

### [[T1018]] - Remote System Discovery

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1018
> technique_name:: Remote System Discovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect discovery of remote systems through net view, nltest, arp, ping sweeps, or PowerShell network enumeration.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Remote System Discovery Commands
// Focus: Host/domain/network enumeration utilities
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(net|nltest|arp|ping|powershell|pwsh|cmd)\.exe$/i
| CommandLine=/(net\s+view|nltest\s+\/domain_trusts|arp\s+-a|ping\s+-n|Test-NetConnection|Get-NetNeighbor|Get-ADComputer)/i
| groupBy([aid, ComputerName, UserName, ParentBaseFileName], function=[count(as=cmd_count), collect(CommandLine, limit=20)])
| cmd_count >= 3
| select([ComputerName, aid, UserName, ParentBaseFileName, cmd_count, CommandLine])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Multiple remote system discovery commands grouped by host/user/parent.
* Triage Steps: Correlate with network fan-out and administrative context; investigate if launched by Office, browser, web worker, or unknown binary.
* Potential False Positives: Network troubleshooting and admin scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"net.exe","CommandLine":"net view /domain"}
```

---

### [[T1049]] - System Network Connections Discovery

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1049
> technique_name:: System Network Connections Discovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect collection of local network connection state using netstat/Get-NetTCPConnection, often used before lateral movement or exfiltration.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Network Connection Enumeration
// Focus: netstat and PowerShell connection listing
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(netstat|powershell|pwsh|cmd)\.exe$/i
| CommandLine=/(netstat\s+(-ano|-anob|-rn)|Get-NetTCPConnection|Get-NetUDPEndpoint|Get-NetRoute)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Network connection and route enumeration commands.
* Triage Steps: Review adjacent discovery cluster and whether output was redirected to files.
* Potential False Positives: Troubleshooting, NOC/SOC diagnostics, EDR support collection.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"netstat.exe","CommandLine":"netstat -ano"}
```

---

### [[T1082]] - System Information Discovery

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect system profiling commands commonly run after initial execution.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: System Profiling Command Cluster
// Focus: systeminfo/wmic/Get-ComputerInfo/dxdiag commands
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(systeminfo|wmic|powershell|pwsh|cmd|dxdiag)\.exe$/i
| CommandLine=/(systeminfo|Get-ComputerInfo|wmic\s+(os|computersystem|qfe|bios)|dxdiag|ver\b)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Host profiling commands and WMI classes.
* Triage Steps: Check whether this is part of a broader discovery burst and identify parent process.
* Potential False Positives: IT inventory and troubleshooting.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"systeminfo.exe","CommandLine":"systeminfo"}
```

---

### [[T1082]] - System Information Discovery — CQL Hub: Enriched Process Tree Association Events

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: AssociateTreeIdWithRoot_to_Pattern_Details.yml
> cql_hub_name:: Enriched Process Tree Association Events
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: The query filters for AssociateTreeIdWithRoot events, joins them with detection-pattern metadata 
from a CSV file, and outputs key fields like timestamp, host, pattern details 
and severity for analysis. In short, it enriches process-tree association events
with contextual detection information.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`AssociateTreeIdWithRoot_to_Pattern_Details.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=AssociateTreeIdWithRoot
| PatternId =~ match(file="falcon/investigate/detect_patterns.csv", column=PatternId, strict=false)
| select([@timestamp, aid, ComputerName, PatternId,name,scenario,scenarioFriendly,description,severity,show_in_ui,killchain_stage,tactic,technique,objective,pattern_updated])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: ## [AssociateTreeIdWithRoot](https://docs.crowdstrike.com/r/associatetreeidwithroot) This event is generated when there is a detection in the sensor. This event has a data field called PatternId that contains a pattern ID. Pattern IDs correspond to a detection.  Reference[GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/AssociateTreeIdWithRoot%20to%20Pattern%20Details.md)
* Key Indicators: Review query output fields and filters from `AssociateTreeIdWithRoot_to_Pattern_Details.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Decode SignInfoFlags

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Decode_SignInfoFlags.yml
> cql_hub_name:: Decode SignInfoFlags
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: The query decodes SignInfoFlags from Windows process events to identify signature details and highlight unsigned or improperly signed executables.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Decode_SignInfoFlags.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 UserSid=/^S-1-5-21-/ SignInfoFlags=*
| bitfield:extractFlags(
 field=SignInfoFlags,
  output=[
    [0,SIGNATURE_FLAG_SELF_SIGNED],
    [1,SIGNATURE_FLAG_MS_SIGNED],
    [2,SIGNATURE_FLAG_TEST_SIGNED],
    [3,SIGNATURE_FLAG_MS_CROSS_SIGNED],
    [4,SIGNATURE_FLAG_CAT_SIGNED],
    [5,SIGNATURE_FLAG_DRM_SIGNED],
    [6,SIGNATURE_FLAG_DRM_TEST_SIGNED],
    [7,SIGNATURE_FLAG_MS_CAT_SIGNED],
    [8,SIGNATURE_FLAG_CATALOGS_RELOADED],
    [9,SIGNATURE_FLAG_NO_SIGNATURE],
    [10,SIGNATURE_FLAG_INVALID_SIGN_CHAIN],
    [11,SIGNATURE_FLAG_SIGN_HASH_MISMATCH],
    [12,SIGNATURE_FLAG_NO_CODE_KEY_USAGE],
    [13,SIGNATURE_FLAG_NO_PAGE_HASHES],
    [14,SIGNATURE_FLAG_FAILED_CERT_CHECK],
    [15,SIGNATURE_FLAG_NO_EMBEDDED_CERT],
    [16,SIGNATURE_FLAG_FAILED_COPY_KEYS],
    [17,SIGNATURE_FLAG_UNKNOWN_ERROR],
    [18,SIGNATURE_FLAG_HAS_VALID_SIGNATURE],
    [19,SIGNATURE_FLAG_EMBEDDED_SIGNED],
    [20,SIGNATURE_FLAG_3RD_PARTY_ROOT],
    [21,SIGNATURE_FLAG_TRUSTED_BOOT_ROOT],
    [22,SIGNATURE_FLAG_UEFI_ROOT],
    [23,SIGNATURE_FLAG_PRS_WIN81_ROOT],
    [24,SIGNATURE_FLAG_FLIGHT_ROOT],
    [25,SIGNATURE_FLAG_APPLE_SIGNED],
    [26,SIGNATURE_FLAG_ESBCACHE],
    [27,SIGNATURE_FLAG_NO_CACHED_DATA],
    [28,SIGNATURE_FLAG_CERT_EXPIRED],
    [29,SIGNATURE_FLAG_CERT_REVOKED]
])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Decode%20SignInfoFlags.md)
* Key Indicators: Review query output fields and filters from `Decode_SignInfoFlags.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Evaluate Operating System Prevalence

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Evaluate_Operating_System_Prevalence.yml
> cql_hub_name:: Evaluate Operating System Prevalence
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query counts how many Windows endpoints are running each OS version (like Windows 10, Windows 11, etc.) in your CrowdStrike environment. It groups endpoints by their current OS product name and returns the count for each version.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Evaluate_Operating_System_Prevalence.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=OsVersionInfo
| event_platform=Win
| groupBy([aid], function=selectLast([ProductName]), limit=max)
| groupBy([ProductName], function=count(aid, as=endpointCount), limit=max)
| sort(endpointCount, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Evaluate_Operating_System_Prevalence.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: File Write Events with Human-Readable File Sizes

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: File_Write_Events_with_Human-Readable_File_Sizes.yml
> cql_hub_name:: File Write Events with Human-Readable File Sizes
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: The query lists file write events and converts the file size into readable units (KB, MB, GB, or TB), displaying timestamps, host details, filenames, and both raw and formatted file sizes.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`File_Write_Events_with_Human-Readable_File_Sizes.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=/FileWritten$/ 
| case {
    Size>=1099511627776 | CommonSize:=unit:convert(Size, to=T) | format("%,.2f TB",field=["CommonSize"], as="CommonSize");
    Size>=1073741824 | CommonSize:=unit:convert(Size, to=G) | format("%,.2f GB",field=["CommonSize"], as="CommonSize");
    Size>=1048576| CommonSize:=unit:convert(Size, to=M) | format("%,.2f MB",field=["CommonSize"], as="CommonSize");
    Size>1024 | CommonSize:=unit:convert(Size, to=k) | format("%,.3f KB",field=["CommonSize"], as="CommonSize");
    * | CommonSize:=format("%,.0f Bytes",field=["Size"]);
}
| table([@timestamp, aid, ComputerName, FileName, Size, CommonSize])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Case%20to%20convert%20Size%20to%20appropriate%20unit%20of%20measure.md)
* Key Indicators: Review query output fields and filters from `File_Write_Events_with_Human-Readable_File_Sizes.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Remediation - Host Contained

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Host_Contained.yml
> cql_hub_name:: Remediation - Host Contained
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query lists all isolated devices and identifies who initiated the isolation.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Host_Contained.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo=detections EventType = "Event_ExternalApiEvent" ExternalApiType = "Event_UserActivityAuditEvent" OperationName=containment_requested cid=?{cid="*"}
| rename(field=AgentIdString,as=aid)
| join({
$falcon/investigate:aid_base()
| groupBy(aid, function=selectLast([MachineDomain, OU, SiteName, ComputerName]), limit=max)
}, field=aid, include=[MachineDomain, OU, SiteName, ComputerName], mode=left, start=12h)
| default(field=[ComputerName, MachineDomain, OU, SiteName],value="--",replaceEmpty=true)
| field_temp:=?{ComputerName="*"}
| case {
field_temp != /^\*$/ | regex(field=field_temp,regex = "(?<field_matched>.*?)(,|$)", repeat="true") | test(ComputerName==field_matched) | drop([field_matched,field_temp]) ;
field_temp = /\*$/ | ComputerName=* | drop([field_temp]) ;
}
| join({
#repo=sensor_metadata #data_source_name = managedassets-ds
| GatewayMAC != "--" AND GatewayIP != "--"
| groupBy(aid, function=collect([MAC, LocalAddressIP4]), limit=max)
}, field=aid, include=[MAC,LocalAddressIP4], mode=left, start=5d)
| default(field=[LocalAddressIP4, MAC],value="--",replaceEmpty=true)
| timestamp_UTC_readable := formatTime("%FT%T%z", field=@timestamp)
| groupBy([@timestamp, timestamp_UTC_readable, UserId, UserIp, ComputerName, LocalAddressIP4, MAC, aid, cid], limit=max)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Host_Contained.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: List of attachments sent from Outlook

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: attachments_send_by_outlook.yml
> cql_hub_name:: List of attachments sent from Outlook
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`attachments_send_by_outlook.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/content.outlook/i
| aid=?aid
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| FileName=/(winword|excel|powerpnt)\.exe/i
| CommandLine=/Outlook\\(?<ShortFile>\w*\\.*)$/i
| table([@timestamp, aid, TargetProcessId, ShortFile, CommandLine], limit=1000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `attachments_send_by_outlook.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Calculate Last Windows Boot Time

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: calculate_last_windows_boot_time.yml
> cql_hub_name:: Calculate Last Windows Boot Time
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Outputs the last reboot timestamp and calculates the time elapsed since then.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`calculate_last_windows_boot_time.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=AgentOnline event_platform=Win  
| groupBy([aid], function=([selectLast([BaseTime])]))
| LastReboot_milli:=(BaseTime/1000*1024)+978307200
| round("LastReboot_milli")
| LastRebootAgo:=now()-(LastReboot_milli*1000)
| formatDuration("LastRebootAgo", precision=2)
| LastReboot:=formatTime(format="%F %T %Z", field="LastReboot_milli")
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `calculate_last_windows_boot_time.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Count Windows Discovery Commands

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: count_windows_discovery_commands.yml
> cql_hub_name:: Count Windows Discovery Commands
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query counts the execution of discovery / reconnaissance commands.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`count_windows_discovery_commands.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Insert Discovery commands of interest here
event_platform=Win #event_simpleName=ProcessRollup2 FileName=/(whoami|ping|net1?|systeminfo|quser|ipconfig)/iF

// Restrict to non-system UserSid Values
| UserSid=S-1-5-21-*

// User case() to create discovery command counter
| case {
    FileName=/whoami/iF     | whoami:="1";
    FileName=/ping/iF       | ping:="1";
    FileName=/net1?/iF      | net:="1";
    FileName=/systeminfo/iF | systeminfo:="1";
    FileName=/quser/iF      | quser:="1";
    FileName=/ipconfig/iF   | ipconfig:="1";
}

// Aggregate results by duration used in time picker
| groupBy([UserName, UserSid], function=([sum(whoami, as=whoami), sum(ping, as=ping), sum(net, as=net), sum(systeminfo, as=systeminfo), sum(quser, as=quser), sum(ipconfig, as=ipconfig), selectLast([CommandLine])]), limit=max)

// Rename field for clarity
| rename(field="CommandLine", as="LastCommandRun")

// Get total number of discovery commands run per UserName/UserSid key pair
| totalDiscovery:=whoami+ping+net+systeminfo+quser+ipconfig

// Set threshold for commands runs (optional)
| totalDiscovery>5

// Reorder using table for easier reading
| table([UserName, UserSid, totalDiscovery, whoami, ping, net, systeminfo, quser, ipconfig, LastCommandRun])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `count_windows_discovery_commands.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Search for oldest devices

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: device_age.yml
> cql_hub_name:: Search for oldest devices
> cql_hub_author:: ByteRay
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: A query to get the age of devices that have the falcon sensor installed.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`device_age.yml`), author: ByteRay.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName = SensorHeartbeat
| in(field=event_platform, values=[?Platform])
| ComputerName like ?ComputerName
| aid = ?aid
| groupBy([aid, ComputerName], function=session([max(@timestamp),min(@timestamp)]))
| "Last seen" := formatTime("%d-%b-%Y %H:%M:%S", field=_max)
| "First seen" := formatTime("%d-%b-%Y %H:%M:%S", field=_min)
| "Age in h" := _duration/3600000
| age := formatDuration(_duration, precision=2)
| "Age in h" := format(format="%.2f", field=["Age in h"])
| sort(field=_duration)
| drop([@timestamp,_duration,_max,_min])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `device_age.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Falcon Sensor Heartbeat Timechart

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: falcon_sensor_heartbeat_timechart.yml
> cql_hub_name:: Falcon Sensor Heartbeat Timechart
> cql_hub_author:: ByteRay
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query plots a timechart showing the frequency of Falcon sensor heartbeat events across the environment.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`falcon_sensor_heartbeat_timechart.yml`), author: ByteRay.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=SensorHeartbeat
| timeChart(span=30min, function=count(as=SensorHeartbeat))
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `falcon_sensor_heartbeat_timechart.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Get Host Zero Trust Assessment Scores

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: get_host_zero_trust_assessment_scores.yml
> cql_hub_name:: Get Host Zero Trust Assessment Scores
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query outputs a table with hosts including their zero trust scores
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`get_host_zero_trust_assessment_scores.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
event_type=ZeroTrustHostAssessment
| groupBy([aid], function=([selectFromMax(field="@timestamp", include=[scores.os, scores.sensor, scores.overall])]))
| join(query={#data_source_name=aidmaster }, field=[aid], include=[ComputerName, event_platform])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `get_host_zero_trust_assessment_scores.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Hunt for specific Command Line Activity

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: hunt_command_line.yml
> cql_hub_name:: Hunt for specific Command Line Activity
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`hunt_command_line.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid
| CommandLine like ?CommandLine
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| table([aid, FileName, ImageFileName, CommandLine], limit=1000)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `hunt_command_line.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Hunt for a file name

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: hunt_filename.yml
> cql_hub_name:: Hunt for a file name
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`hunt_filename.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid
| ImageFileName like ?ImageFileName
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| table([aid, FileName, ImageFileName, CommandLine], limit=1000)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `hunt_filename.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: List all Identity Protection Detections

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: list_all_identity_protection_detections.yml
> cql_hub_name:: List all Identity Protection Detections
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Identity
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: List of all IDP detections.
* Telemetry Requirements: Identity
* Source: CQL Hub (`list_all_identity_protection_detections.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo=detections ExternalApiType=Event_IdpDetectionSummaryEvent
| rename([[TargetEndpointHostName, TargetEndpoint], [SourceEndpointHostName, SourceEndpoint], [TargetAccountName, TargetAccount], [SourceAccountName, SourceAccount]])
| format("[FalconHostLink](%s)", field=[FalconHostLink], as="FalconHostLink")
| format(format="%s > %s", field=[Tactic, Technique], as=MITRE)
| groupBy([TargetAccount], function=([sum(Severity, as=Weight), count(DetectName, distinct=true, as=UniqueDetections), count(DetectName, as=TotalDetections), collect([MITRE, SourceEndpoint]), selectFromMax(field="@timestamp", include=[FalconHostLink])]))
| rename(field="FalconHostLink", as="Most Recent Detection")
| sort(Weight, order=desc, limit=200)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `list_all_identity_protection_detections.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: OS Platform ratio

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: os_platform_ratio.yml
> cql_hub_name:: OS Platform ratio
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query aggregates SensorHeartbeat events by operating system platform to show the relative distribution of endpoints per OS. It is well suited for visualization as a pie chart, providing a quick overview of platform coverage and identifying imbalances or unexpected OS presence in the environment.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`os_platform_ratio.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName = SensorHeartbeat
| groupBy(aid,event_platform)
| groupBy([event_platform])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `os_platform_ratio.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Find processes that only ran a few of times on a specific host

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: processes_specific_host.yml
> cql_hub_name:: Find processes that only ran a few of times on a specific host
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`processes_specific_host.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid
| groupBy([SHA256HashData, ImageFileName], limit=max)
| _count <5
| sort(_count, limit=1000)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `processes_specific_host.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: Devices in RFM state

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: rfm_state.yml
> cql_hub_name:: Devices in RFM state
> cql_hub_author:: ByteRay
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`rfm_state.yml`), author: ByteRay.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=OsVersionInfo
| groupBy([aid, ComputerNam, RFMState], function=selectLast([@timestamp]))
| RFMState = 1

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `rfm_state.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1082]] - System Information Discovery — CQL Hub: User Logon Details (Time, Type, Location, Last Password Change)

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1082
> technique_name:: System Information Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: user_logon_details__time__type__location__last_password_change_.yml
> cql_hub_name:: User Logon Details (Time, Type, Location, Last Password Change)
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1082
> required_modules:: Insight
> cql_hub_tags:: Hunting, Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query will output a table including recent user logons with context information:
- Timestamp
- UserName
- SID
- LogonType
- UserIsAdmin (Y/N)
- PasswordLastSet
- Location

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`user_logon_details__time__type__location__last_password_change_.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=UserLogon UserSid=S-1-5-21-*
| in(LogonType, values=["2","10"])
| ipLocation(aip)
| case {UserIsAdmin = "1" | UserIsAdmin := "Yes" ;
UserIsAdmin = "0" | UserIsAdmin := "No" ;
* }
| case {
LogonType = "2" | LogonType := "Interactive" ;
LogonType = "3" | LogonType := "Network" ;
LogonType = "4" | LogonType := "Batch" ;
LogonType = "5" | LogonType := "Service" ;
LogonType = "7" | LogonType := "Unlock" ;
LogonType = "8" | LogonType := "Network Cleartext" ;
LogonType = "9" | LogonType := "New Credentials" ;
LogonType = "10" | LogonType := "Remote Interactive" ;
LogonType = "11" | LogonType := "Cached Interactive" ;
* }
| PasswordLastSet := PasswordLastSet*1000
| LogonTime := LogonTime*1000
| PasswordLastSet := formatTime("%Y-%m-%d %H:%M:%S", field=PasswordLastSet, locale=en_US, timezone=Z)
| LogonTime := formatTime("%Y-%m-%d %H:%M:%S", field=LogonTime, locale=en_US, timezone=Z)
| table(["LogonTime", "aid", "UserName", "UserSid", "LogonType", "UserIsAdmin", "PasswordLastSet", "aip.city", "aip.state", "aip.country"])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `user_logon_details__time__type__location__last_password_change_.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1057]] - Process Discovery

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1057
> technique_name:: Process Discovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect task/process enumeration by shells or suspicious parents.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Process Enumeration by Command Line
// Focus: tasklist/Get-Process/wmic process queries
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(tasklist|powershell|pwsh|wmic|cmd)\.exe$/i
| CommandLine=/(tasklist|Get-Process|gwmi\s+win32_process|wmic\s+process|ps\s+-ef)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Process enumeration commands.
* Triage Steps: Correlate with credential access or EDR discovery strings.
* Potential False Positives: Admin troubleshooting and monitoring.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"tasklist.exe","CommandLine":"tasklist /v"}
```

---

### [[T1482]] - Domain Trust Discovery

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1482
> technique_name:: Domain Trust Discovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect enumeration of domain trusts and forest relationships.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Domain Trust Enumeration
// Focus: nltest/domain_trusts, netdom trust, PowerView trust commands
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(nltest|netdom|powershell|pwsh)\.exe$/i
| CommandLine=/(\/domain_trusts|netdom\s+trust|Get-ADTrust|Get-DomainTrust|Get-ForestTrust)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Trust enumeration commands.
* Triage Steps: Validate if user is identity admin; inspect subsequent lateral movement to trusted domains.
* Potential False Positives: Domain admin troubleshooting.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"nltest.exe","CommandLine":"nltest /domain_trusts /all_trusts"}
```

---

### [[T1135]] - Network Share Discovery

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1135
> technique_name:: Network Share Discovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect enumeration of shares via net view, PowerShell SMB cmdlets, or WMI.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Network Share Enumeration
// Focus: net view /all, Get-SmbShare, Win32_Share queries
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(net|powershell|pwsh|wmic|cmd)\.exe$/i
| CommandLine=/(net\s+view.*\/all|net\s+view\s+\\\\|Get-SmbShare|Get-SmbMapping|Win32_Share|smbclient\s+-L)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Share enumeration commands and UNC targets.
* Triage Steps: Determine target hosts/shares and whether file collection followed.
* Potential False Positives: Admin share audits and helpdesk troubleshooting.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"net.exe","CommandLine":"net view \\fileserver /all"}
```

---

### [[T1135]] - Network Share Discovery — CQL Hub: SMB Enumeration | Defender for Identity

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1135
> technique_name:: Network Share Discovery
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: smb_enumeration_defender.yml
> cql_hub_name:: SMB Enumeration | Defender for Identity
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1135
> related_mitre_ids:: T1135
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This detection query will detect SMB Enumeration based on the Microsoft defender for Identity Module

* Telemetry Requirements: Identity
* Source: CQL Hub (`smb_enumeration_defender.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1135.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor="microsoft"
| #event.module="defender-identity"
| Vendor.category="AdvancedHunting-IdentityDirectoryEvents"
| event.action="smb session"
| #event.outcome="success"
| groupBy([user.name, source.address], function=[count(as=smb_sessions), count(Vendor.properties.DestinationDeviceName, distinct=true, as=unique_destinations), collect(Vendor.properties.DestinationDeviceName, limit=50), collect(Vendor.properties.AdditionalFields.DestinationComputerOperatingSystem, limit=20), min(@timestamp, as=start_time), max(@timestamp, as=end_time)], limit=20000)
| unique_destinations >= 3
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 10
| start_time_fmt := formatTime(format="%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime(format="%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort(unique_destinations, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `smb_enumeration_defender.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1135]] - Network Share Discovery — CQL Hub: Users creating Network Shares

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1135
> technique_name:: Network Share Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: users_creating_network_shares.yml
> cql_hub_name:: Users creating Network Shares
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1135
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: The Query shows all new created Network Shares.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`users_creating_network_shares.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName="NetShareAdd"
| wildcard(field=UserName, pattern=?UserName, ignoreCase=true)
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| groupBy([ComputerName, UserName, ShareName, SharePath, ShareData, @timestamp])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `users_creating_network_shares.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1518.001]] - Security Software Discovery

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1518.001
> technique_name:: Security Software Discovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect commands enumerating AV/EDR products, security services, or sensor processes.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Security Tool Discovery
// Focus: Defender/EDR service and process enumeration
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|wmic|sc|tasklist|reg|cmd)\.exe$/i
| CommandLine=/(WinDefend|Sense|SecurityHealthService|CrowdStrike|Falcon|CSFalcon|CarbonBlack|SentinelAgent|Defender|Get-MpComputerStatus|AntiVirusProduct|tasklist.*(csfalcon|sense|defender))/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Security product names in process/service/registry discovery commands.
* Triage Steps: Review parent process and whether disablement follows.
* Potential False Positives: SOC/IT diagnostics and compliance scans.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Get-MpComputerStatus; tasklist | findstr /i falcon"}
```

---

### [[T1124]] - System Time Discovery

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1124
> technique_name:: System Time Discovery
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Low
> tags:: CQL, MITRE/Discovery

* Detection Objective: Detect time and timezone discovery commands used for sandbox evasion, scheduling, or operator context.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: System Time and Timezone Discovery
// Focus: time/date/w32tm/tzutil commands from suspicious parents
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(cmd|powershell|pwsh|w32tm|tzutil)\.exe$/i
| CommandLine=/(\btime\s+\/t|\bdate\s+\/t|Get-Date|w32tm\s+\/query|tzutil\s+\/g|Get-TimeZone)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Time and timezone query commands.
* Triage Steps: Use as context with other discovery/execution signals rather than standalone alerting.
* Potential False Positives: User/admin troubleshooting and scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"tzutil.exe","CommandLine":"tzutil /g"}
```

---

### [[T1046]] - Network Service Discovery — CQL Hub: Rare Remote Ports in Network Connections

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1046
> technique_name:: Network Service Discovery
> logscale_stream:: Endpoint, Network
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Bottom_10_Percent_of_NetworkConnct_Port_Values.yml
> cql_hub_name:: Rare Remote Ports in Network Connections
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1046
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: The query analyzes IPv4 network connection events, counts occurrences per remote port, calculates their percentage of total connections, and lists only ports representing less than 10% of the traffic.
* Telemetry Requirements: Endpoint, Network
* Source: CQL Hub (`Bottom_10_Percent_of_NetworkConnct_Port_Values.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=NetworkConnectIP4
| groupBy([RemotePort], function=count(as=count), limit=max) 
| [sum(count, as=total), sort(field=RemotePort, order=ascending, limit=20000)] 
| percent := 100 * (count / total) 
| drop([total]) 
| percent < 10

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Bottom%2010%25%20of%20NetworkConnct%20Port%20Values.md)
* Key Indicators: Review query output fields and filters from `Bottom_10_Percent_of_NetworkConnct_Port_Values.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1046]] - Network Service Discovery — CQL Hub: External Connectons with Process

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1046
> technique_name:: Network Service Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: External_Connectons_with_Process.yml
> cql_hub_name:: External Connectons with Process
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1046
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`External_Connectons_with_Process.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=NetworkConnectIP4 aid=?aid ComputerName=?Computername RemoteAddressIP4=?RemoteIP 
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","192.168.0.0/16","172.16.0.0/12","127.0.0.0/8"])
| join({#event_simpleName=ProcessRollup2  FileName=?Processname }, field=[ContextProcessId],key=TargetProcessId, include=[FileName, UserName,ImageFileName, RemoteAddressIP4, RemotePort,CommandLine], mode=left)
| groupBy(UserName, function=collect([FileName, UserName, ImageFileName, RemoteIP, RPort, CommandLine]))
| sort([_count], order=asc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `External_Connectons_with_Process.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1046]] - Network Service Discovery — CQL Hub: Falcon Sensor Support Status

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1046
> technique_name:: Network Service Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: falcon_sensor_support_status.yml
> cql_hub_name:: Falcon Sensor Support Status
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1046
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query lists all active falcon sensors including their release date and support end date.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`falcon_sensor_support_status.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo=sensor_metadata #data_source_name=aidmaster #data_source_group=aidmaster-api
| groupBy([aid], function=([selectFromMax(field="@timestamp", include=[ComputerName, Time, Version, ConfigIDBuild, AgentVersion])]))
| match(file="falcon/helper/sensors_support_info.csv", field=ConfigIDBuild, column=BUILD, ignoreCase=true, strict=true)
| parseTimestamp("M/d/yy",field=SUPPORT_ENDS, as=SUPPORT_ENDS_EPOCH, timezone="UTC")
| case{
    test(now()>SUPPORT_ENDS_EPOCH) | SUPPORTED:="NO";
    * | SUPPORTED:="YES";
}
| groupBy([PLATFORM, VERSION_FAMILY, SUPPORTED], function=([count(aid, as=Count), collect([RELEASE_DATE, SUPPORT_ENDS])]))
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `falcon_sensor_support_status.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1069.002]] - Domain Groups — CQL Hub: Domain Admin Enumeration

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1069.002
> technique_name:: Domain Groups
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: domain_admin_enumeration.yml
> cql_hub_name:: Domain Admin Enumeration
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1069.002
> related_mitre_ids:: T1069.002
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query will detect Domain Admin Enumeration based on the Microsoft Defender for Identity Module

* Telemetry Requirements: Identity
* Source: CQL Hub (`domain_admin_enumeration.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1069.002.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor="microsoft"
| #event.dataset = "defender-identity.IdentityQueryEvents"
| Vendor.properties.QueryType ="AllDomainAdminsOrEnterpriseAdmins"
| table([@timestamp,host.name,destination.address,Vendor.properties.Query,Vendor.properties.AdditionalFields.SearchFilter,Vendor.properties.AdditionalFields.LdapSearchScope])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This query will detect Domain Admin enumeration based on the Microsoft defender for Identity log sources.
* Key Indicators: Review query output fields and filters from `domain_admin_enumeration.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1526]] - Cloud Service Discovery — CQL Hub: Identify Shadow SaaS

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1526
> technique_name:: Cloud Service Discovery
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: identify_shadow_saas.yml
> cql_hub_name:: Identify Shadow SaaS
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1526
> related_mitre_ids:: T1526
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: This query identifies SaaS services supported by Falcon Shield and helps detect which SaaS products are actively used within the environment.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`identify_shadow_saas.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1526.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=DnsRequest DomainName=*
| match(file="shadow-saas.csv", field=[DomainName], column=[Domains], strict=true,mode=glob)
| Category=?Category
| Vendor=?Vendor
| Application=?Application
| groupBy(ComputerName, Vendor, Application, Category)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `identify_shadow_saas.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1526]] - Cloud Service Discovery — CQL Hub: Identity Protection - Average Cloud Response Time

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1526
> technique_name:: Cloud Service Discovery
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: identity_protection___average_cloud_response_time.yml
> cql_hub_name:: Identity Protection - Average Cloud Response Time
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1526
> required_modules:: Identity
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Average time (in seconds) the cloud service takes to resolve entity information (e.g., from SID/GUID). Latency above 3 seconds may cause intermittent issues; above 4 seconds can lead to recurring timeouts.
* Telemetry Requirements: Identity
* Source: CQL Hub (`identity_protection___average_cloud_response_time.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo=base_sensor #event_simpleName=IdpTelemetryData
| in(field=cid, values=[?SelectedCid])
| match(file="aid_master_main.csv", field=[cid, aid])
| in(field=MachineDomain, values=[?SelectedDomain])
| IdpTelemetryObjectArrayV2=/{"_name":"IdpTelemetryObject","identifier":\["CloudFetcher\/CloudResponseTime"\],"statistics_features":\[{"_name":"IdpTelemetryObjectStatisticsFeatures","average":\["(?<CloudResponseTimeAverage>\d+)"\],"median":\["(?<CloudResponseTimeMedian>\d+)"\],"p95_value":\["(?<CloudResponseTimeP95_value>\d+)"\],"p99_value":\["(?<CloudResponseTimeP99_value>\d+)"\]}]}/
| CloudResponseTimeAverage:=CloudResponseTimeAverage/10000000
| timeChart(function=avg("CloudResponseTimeAverage"))
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `identity_protection___average_cloud_response_time.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1087]] - Account Discovery — CQL Hub: LDAP Enumeration

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1087
> technique_name:: Account Discovery
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: ldap_enumeration.yml
> cql_hub_name:: LDAP Enumeration
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1087
> related_mitre_ids:: T1087
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Detects suspicious or excessive LDAP queries performed against Active Directory, as identified by Microsoft Defender for Identity. This behavior may indicate reconnaissance activity where an attacker attempts to gather information about users, groups, and domain structure for further exploitation

* Telemetry Requirements: Identity
* Source: CQL Hub (`ldap_enumeration.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1087.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.dataset="defender-identity.IdentityQueryEvents"
| event.action = "ldap query"
| groupBy([Vendor.properties.IPAddress,Vendor.properties.AdditionalFields.FROM.DEVICE], function=[count(as=ldap_queries),collect(fields=[Vendor.properties.DestinationDeviceName,Vendor.properties.Query,Vendor.properties.AdditionalFields.TARGET_OBJECT.ENTITY_USER,Vendor.properties.AdditionalFields.TARGET_OBJECT.GROUP,Vendor.properties.QueryTarget,Vendor.properties.TargetAccountUpn]),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| ldap_queries > 50 //Adjust the value as per your enviorment
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 100 //Adjust the time as per your enviorment
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([ldap_queries], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects suspicious or excessive LDAP queries performed against Active Directory, as identified by Microsoft Defender for Identity. This behavior may indicate reconnaissance activity where an attacker attempts to gather information about users, groups, and domain structure for further exploitation
* Key Indicators: Review query output fields and filters from `ldap_enumeration.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1087]] - Account Discovery — CQL Hub: SAMR Burst (BloodHound/PowerView)

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1087
> technique_name:: Account Discovery
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: samr_burst_bloodhound_powerview.yml
> cql_hub_name:: SAMR Burst (BloodHound/PowerView)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1087
> related_mitre_ids:: T1087
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Detects abnormal or high‑volume Security Account Manager (SAMR) queries against Active Directory, often associated with tools like BloodHound or PowerView. This behavior typically indicates reconnaissance activity where an attacker is rapidly enumerating users, groups, and permissions to map the environment.

* Telemetry Requirements: Identity
* Source: CQL Hub (`samr_burst_bloodhound_powerview.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1087.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.dataset="defender-identity.IdentityQueryEvents"
| event.action = "samr query"
| groupBy([user.name, source.address], function=[count(as=samr_queries),count(field=Vendor.properties.DestinationDeviceName, distinct=true, as=unique_destinations),collect(fields=[Vendor.properties.DestinationDeviceName,Vendor.properties.DestinationIPAddress,Vendor.properties.QueryType,Vendor.properties.QueryTarget]),collect(fields=Vendor.properties.DeviceName),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| samr_queries > 100 //Adjust the value  as per your environment
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 10 //Adjust the time as per your environment
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([samr_queries], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This query detects potential Active Directory enumeration by identifying users and source addresses that perform a high volume of SAMR (Security Account Manager Remote) queries against multiple destinations. It flags accounts that exceed 100 SAMR queries within a 10-minute window, which is a common indicator of tools like BloodHound or net.exe being used to enumerate AD objects
* Key Indicators: Review query output fields and filters from `samr_burst_bloodhound_powerview.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1087]] - Account Discovery — CQL Hub: Windows authentication traffic metrics

> [!metadata]+ Detection Metadata
> tactic:: Discovery
> technique_id:: T1087
> technique_name:: Account Discovery
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: windows_authentication_traffic_metrics.yml
> cql_hub_name:: Windows authentication traffic metrics
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1087
> required_modules:: Identity
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Discovery, CQL_Hub

* Detection Objective: Displays Windows-collected authentication traffic metrics from your domain controllers, including Kerberos authentications, NTLM authentications, LDAP binds, and LDAP searches per second. These are native Windows performance counters and do not represent traffic inspected by Identity Protection - they provide baseline visibility into overall domain controller activity.
* Telemetry Requirements: Identity
* Source: CQL Hub (`windows_authentication_traffic_metrics.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo=base_sensor #event_simpleName="IdpDcPerfReport"
| aid=?SelectedAid
| IdpPerfCounterAvg:= IdpPerfCounterSum / IdpPerfSampleCount
| timeChart(span=15m, function=[avg("IdpPerfCounterAvg")], series=IdpPerfCounterPath)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `windows_authentication_traffic_metrics.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
