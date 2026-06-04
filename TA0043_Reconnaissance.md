# TA0043 - Reconnaissance

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Reconnaissance. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1595]] - Active Scanning

> [!metadata]+ Detection Metadata
> tactic:: Reconnaissance
> technique_id:: T1595
> technique_name:: Active Scanning
> logscale_stream:: NetworkConnectIP4
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Reconnaissance

* Detection Objective: Detect endpoint-originated network sweep behavior where a scripting, shell, or admin tool initiates many unique outbound connections in a short window. This identifies internal reconnaissance and external scan staging that often precedes exploitation.
* Telemetry Requirements: NetworkConnectIP4, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: High Fan-Out Endpoint Network Scanning
// Focus: Single process contacting many hosts or ports in a short window
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=*
| RemotePort=*
| NOT cidr(RemoteAddressIP4, subnet=["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"])
| ImageFileName=/\\(powershell|pwsh|cmd|python|nmap|masscan|nc|netcat|curl|wget)\.exe$/i
| groupBy([aid, ComputerName, ImageFileName, ContextProcessId], function=[count(RemoteAddressIP4, distinct=true, as=unique_remote_ips), count(RemotePort, distinct=true, as=unique_remote_ports), count(as=connection_count), collect([RemoteAddressIP4, RemotePort], limit=20)])
| unique_remote_ips >= 25 OR unique_remote_ports >= 20 OR connection_count >= 100
| sort(connection_count, order=desc)
| select([ComputerName, aid, ImageFileName, ContextProcessId, unique_remote_ips, unique_remote_ports, connection_count, RemoteAddressIP4, RemotePort])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: High unique_remote_ips/unique_remote_ports, scanner-like process image, and rapid connection_count growth.
* Triage Steps: Pivot from ContextProcessId to ProcessRollup2 and validate user, parent process, and command line. Confirm whether the destination set matches an approved vulnerability scanner or admin subnet.
* Potential False Positives: Vulnerability scanners, EDR inventory tools, software deployment agents, and approved network monitoring utilities.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"NetworkConnectIP4","ImageFileName":"\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","RemoteAddressIP4":"10.20.30.40","RemotePort":445,"ComputerName":"WS-043"}
```

---

### [[T1595]] - Active Scanning — CQL Hub: Systems Initiating Connections to a High Number of Ports

> [!metadata]+ Detection Metadata
> tactic:: Reconnaissance
> technique_id:: T1595
> technique_name:: Active Scanning
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: systems_initiating_connections_to_a_high_number_of_ports.yml
> cql_hub_name:: Systems Initiating Connections to a High Number of Ports
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1595, T1046
> related_mitre_ids:: T1595, T1046
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Reconnaissance, CQL_Hub

* Detection Objective: Detects hosts that establish network connections across a large number of unique ports within a given period. This behavior may indicate port scanning, network reconnaissance, or potentially malicious enumeration activity originating from a compromised host or unauthorized tool.
The query aggregates by host and process, listing associated filenames, command lines, and user context to assist with triage.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`systems_initiating_connections_to_a_high_number_of_ports.yml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1595, T1046.
* Related/Resolved MITRE IDs: T1595, T1046.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=/^(NetworkConnectIP4|ProcessRollup2)$/
| falconPID:=TargetProcessId | falconPID:=ContextProcessId
| UserID:=UserSid | UserID:=UID
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=NetworkConnectIP4}, {#event_simpleName=ProcessRollup2}])
| groupBy([aid, ComputerName, falconPID], function=([
	collect([FileName, CommandLine, UserName, UserID]), 
	count(RemotePort, as=uniquePortCount), 
	collect([RemotePort], separator=", ", limit=25), 
	count(RemoteAddressIP4, distinct=true, as=remoteIPcount)
	]), limit=max)
| FileName=* RemotePort=*
| test(uniquePortCount>25)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `systems_initiating_connections_to_a_high_number_of_ports.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1592]] - Gather Victim Host Information

> [!metadata]+ Detection Metadata
> tactic:: Reconnaissance
> technique_id:: T1592
> technique_name:: Gather Victim Host Information
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Reconnaissance

* Detection Objective: Detect scripted host profiling commands that enumerate OS, patch, domain, and hardware information. The logic emphasizes clustered discovery commands rather than a single benign command.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Clustered Host Profiling Commands
// Focus: Reconnaissance commands executed by shells or scripts
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(systeminfo|hostname|whoami|ipconfig|nltest|net|wmic|powershell|cmd)\.exe$/i
| CommandLine=/(systeminfo|whoami\s+\/all|ipconfig\s+\/all|nltest\s+\/dclist|net\s+(config|view|user|group)|wmic\s+(computersystem|qfe|os)|Get-ComputerInfo)/i
| groupBy([aid, ComputerName, UserName, ParentBaseFileName], function=[count(as=cmd_count), count(ImageFileName, distinct=true, as=distinct_tools), collect(CommandLine, limit=15)])
| cmd_count >= 4 OR distinct_tools >= 3
| sort(cmd_count, order=desc)
| select([ComputerName, aid, UserName, ParentBaseFileName, cmd_count, distinct_tools, CommandLine])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Multiple host/domain profiling commands under a common parent or user context.
* Triage Steps: Review parent process and logon context; correlate to Initial Access or Execution techniques such as [[T1059]] and [[T1204]].
* Potential False Positives: IT support scripts, endpoint audit scripts, configuration-management baselines.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"systeminfo.exe","CommandLine":"systeminfo && whoami /all && ipconfig /all","ParentBaseFileName":"cmd.exe"}
```

---

### [[T1590]] - Gather Victim Network Information

> [!metadata]+ Detection Metadata
> tactic:: Reconnaissance
> technique_id:: T1590
> technique_name:: Gather Victim Network Information
> logscale_stream:: DnsRequest
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Reconnaissance

* Detection Objective: Detect repeated DNS and connectivity probes for externally exposed services or internal network ranges. This models pre-intrusion or post-compromise reconnaissance when performed from managed endpoints.
* Telemetry Requirements: DnsRequest, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Network and Service Reconnaissance Burst
// Focus: High-volume DNS and connectivity probing by one process
#event_simpleName=DnsRequest
| DomainName=/(vpn|mail|owa|adfs|sso|citrix|rdp|remote|portal|git|jira|confluence)\./i
| groupBy([aid, ComputerName, ContextProcessId], function=[count(as=query_count), count(DomainName, distinct=true, as=unique_names), collect(DomainName, limit=25)])
| query_count >= 20 OR unique_names >= 10
| sort(query_count, order=desc)
| select([ComputerName, aid, ContextProcessId, query_count, unique_names, DomainName])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Service-discovery hostnames and high unique DNS query volume.
* Triage Steps: Resolve ContextProcessId to process and validate whether this is browser activity, scanner activity, or scripted recon.
* Potential False Positives: Browser prefetch, vulnerability scanners, VPN/SASE agents.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"DnsRequest","DomainName":"owa.example.com","ComputerName":"WS-101","ContextProcessId":"1234"}
```

---

### [[T1598]] - Phishing for Information

> [!metadata]+ Detection Metadata
> tactic:: Reconnaissance
> technique_id:: T1598
> technique_name:: Phishing for Information
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Low
> tags:: CQL, MITRE/Reconnaissance

* Detection Objective: Detect local preparation for credential-harvesting phishing using web tooling or scripting utilities on endpoints. This is lower confidence but useful for insider or compromised workstation hunting.
* Telemetry Requirements: ProcessRollup2, DnsRequest

#### Production-Ready CQL Query:

```cql
// Title: Credential Harvesting Page Kit Staging
// Focus: Web/script tooling creating or serving login-themed pages
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(python|node|php|powershell|pwsh|cmd)\.exe$/i
| CommandLine=/(http\.server|SimpleHTTPServer|npm\s+start|php\s+-S|login|credential|password|oauth|sso|mfa)/i
| CommandLine=/(\\Users\\|\\ProgramData\\|\\Temp\\|Desktop|Downloads)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Local lightweight web server or dev runtime with credential-themed paths/strings.
* Triage Steps: Inspect working directory and served files; correlate to outbound DNS/domain-registration activity if available.
* Potential False Positives: Developers testing auth pages, local labs, security awareness teams.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"python.exe","CommandLine":"python -m http.server 8080 --directory C:\\Users\\bob\\Downloads\\sso-login"}
```
