# TA0008 - Lateral Movement

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Lateral Movement. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1021.002]] - SMB/Windows Admin Shares

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1021.002
> technique_name:: SMB/Windows Admin Shares
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Lateral_Movement

* Detection Objective: Detect remote copy or execution over administrative shares. The logic captures xcopy/copy/robocopy/net use patterns targeting ADMIN$, C$, or IPC$.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Admin Share Copy or Execution
// Focus: SMB admin share paths and copy/execution utilities
#event_simpleName=ProcessRollup2
| CommandLine=/\\\\[^\\]+\\(ADMIN\$|C\$|IPC\$|Windows\\Temp)/i
| ImageFileName=/\\(cmd|copy|xcopy|robocopy|net|powershell|wmic|psexec)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: UNC admin-share path and file transfer or remote execution utility.
* Triage Steps: Identify target host and copied binary; correlate with service creation [[T1543.003]] or WMI execution [[T1047]].
* Potential False Positives: Software deployment, backup, and admin maintenance.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"cmd.exe","CommandLine":"copy payload.exe \\\\HOST2\\ADMIN$\\Temp\\payload.exe"}
```

---

### [[T1021.002]] - SMB/Windows Admin Shares — CQL Hub: SMB File Copy to Multiple Devices (Microsoft Defender for Identity)

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1021.002
> technique_name:: SMB/Windows Admin Shares
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: smb_file_copy_to_multiple_devices_microsoft_defender_for_identity.yml
> cql_hub_name:: SMB File Copy to Multiple Devices (Microsoft Defender for Identity)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1021.002
> related_mitre_ids:: T1021.002
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Lateral_Movement, CQL_Hub

* Detection Objective: Detects instances where files are copied over SMB to multiple devices within a short timeframe, as identified by Microsoft Defender for Identity. This behavior may indicate lateral movement where an attacker distributes tools or payloads across systems to expand access and establish control.

* Telemetry Requirements: Identity
* Source: CQL Hub (`smb_file_copy_to_multiple_devices_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1021.002.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityDirectoryEvents"
| Vendor.properties.ActionType = "SMB file copy"
| groupBy([user.name, source.address], function=[count(as=file_copies),count(field=Vendor.properties.DestinationDeviceName, distinct=true, as=unique_destinations),collect(fields=Vendor.properties.DestinationDeviceName),collect(fields=[Vendor.properties.DeviceName,Vendor.properties.AdditionalFields.FileName]),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| unique_destinations >= 1
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 30
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([unique_destinations], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects instances where files are copied over SMB to multiple devices within a short timeframe, as identified by Microsoft Defender for Identity. This behavior may indicate lateral movement where an attacker distributes tools or payloads across systems to expand access and establish control.
* Key Indicators: Review query output fields and filters from `smb_file_copy_to_multiple_devices_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1021.006]] - Windows Remote Management

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1021.006
> technique_name:: Windows Remote Management
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Lateral_Movement

* Detection Objective: Detect WinRM and PowerShell remoting usage with suspicious remote command payloads.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: PowerShell Remoting or WinRM Remote Execution
// Focus: Enter-PSSession/Invoke-Command/winrs with encoded or shell payloads
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|winrs)\.exe$/i
| CommandLine=/(Invoke-Command|Enter-PSSession|New-PSSession|winrs\s+-r:|ComputerName).*(cmd|powershell|whoami|ipconfig|-enc|DownloadString)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: PowerShell remoting or winrs with command execution payload.
* Triage Steps: Validate source/destination, account, and whether CredSSP/delegation was involved.
* Potential False Positives: Legitimate administrative remoting.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Invoke-Command -ComputerName HOST2 -ScriptBlock { whoami }"}
```

---

### [[T1021.001]] - Remote Desktop Protocol

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1021.001
> technique_name:: Remote Desktop Protocol
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Lateral_Movement

* Detection Objective: Detect command-line RDP session initiation, saved credential use, or RDP-related discovery from non-admin contexts.
* Telemetry Requirements: ProcessRollup2, UserLogon, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: RDP Session Initiation or Credentialed Launch
// Focus: mstsc/cmdkey patterns and RDP target usage
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(mstsc|cmdkey|runas)\.exe$/i
| CommandLine=/(mstsc.*\/v:|cmdkey.*\/generic:TERMSRV|\/savecred|runas.*\/netonly)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: RDP target and saved credential usage.
* Triage Steps: Validate destination, account, and whether session aligns to user role.
* Potential False Positives: Normal administrator RDP activity.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"cmdkey.exe","CommandLine":"cmdkey /generic:TERMSRV/SRV2 /user:domain\\admin /pass:***"}
```

---

### [[T1021.001]] - Remote Desktop Protocol — CQL Hub: Lateral Movement Detection

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1021.001
> technique_name:: Remote Desktop Protocol
> logscale_stream:: Network
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Lateral_Movement_Detection.yml
> cql_hub_name:: Lateral Movement Detection
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1021.001, T1021.002, T1135
> related_mitre_ids:: T1021.001, T1021.002, T1135
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Lateral_Movement, CQL_Hub

* Detection Objective: This query identifies potential lateral movement activities by detecting remote connections and credential usage patterns across multiple hosts.
* Telemetry Requirements: Network
* Source: CQL Hub (`Lateral_Movement_Detection.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1021.001, T1021.002, T1135.
* Related/Resolved MITRE IDs: T1021.001, T1021.002, T1135.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=NetworkConnect 
| (RemotePort=445 OR RemotePort=3389 OR RemotePort=5985)
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| join({#event_simpleName=ProcessRollup2}, field=[aid, RawProcessId], include=[ImageFileName, CommandLine])
| join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])
| table([aid, UserName, ImageFileName, RemoteAddressIP4, RemotePort, CommandLine])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This query uses CrowdStrike Query Language (CQL) to detect lateral movement activities:  1. **Network Connections**: `#event_simpleName=NetworkConnect`    - Monitors outbound network connections from endpoints  2. **Target Ports**: `(RemotePort=445 OR RemotePort=3389 OR RemotePort=5985)`    - Focuses on SMB (445), RDP (3389), and WinRM (5985) connections  3. **External Targets**: `!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])`    - Excludes internal network ranges to focus on external connections  4. **Process Context**: `join({#event_simpleName=ProcessRollup2}, field=[aid, RawProcessId], include=[ImageFileName, CommandLine])`    - Adds process information for the connecting application  5. **User Context**: `join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])`    - Enriches with user account information  6. **Output**: `table([aid, UserName, ImageFileName, RemoteAddressIP4, RemotePort, CommandLine])`    - Shows user, process, target IP, and connection details
* Key Indicators: Review query output fields and filters from `Lateral_Movement_Detection.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1021.001]] - Remote Desktop Protocol — CQL Hub: Potential Lateral Movement through RDP

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1021.001
> technique_name:: Remote Desktop Protocol
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: potential_lateral_movement_through_rdp.yml
> cql_hub_name:: Potential Lateral Movement through RDP
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1021.001
> related_mitre_ids:: T1021.001
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Lateral_Movement, CQL_Hub

* Detection Objective: Detects when a user account initiates Remote Desktop Protocol (RDP) sessions across multiple systems within a short timeframe, as identified by Microsoft Defender for Identity. This behavior may indicate potential lateral movement by an attacker or unauthorized use of administrative access

* Telemetry Requirements: Identity
* Source: CQL Hub (`potential_lateral_movement_through_rdp.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1021.001.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityLogonEvents"
| network.protocol = "kerberos" or network.protocol = "ntlm"
| Vendor.properties.LogonType="Remote desktop"
| groupBy([user.name], function=[count(as=lateral_moves),count(field=Vendor.properties.TargetDeviceName, distinct=true, as=unique_devices),collect(fields=[Vendor.properties.DeviceName,Vendor.properties.TargetDeviceName,source.address]),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| unique_devices > 1 //Adjust the value as per enviorment
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 60 //Adjust the time as per enviorment
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([unique_devices], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This query detects potential lateral movement activity by analyzing Kerberos/NTLM remote desktop logon events from Microsoft Defender for Identity. It groups authentication events by username and flags users who logged into more than one unique device within a 60-minute window.
* Key Indicators: Review query output fields and filters from `potential_lateral_movement_through_rdp.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1570]] - Lateral Tool Transfer

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1570
> technique_name:: Lateral Tool Transfer
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Lateral_Movement

* Detection Objective: Detect transfer of tools to remote admin shares or Windows temp paths before remote execution.
* Telemetry Requirements: ProcessRollup2, FileWritten, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Tool Transfer to Remote Host
// Focus: copy/robocopy/xcopy/scp to UNC admin paths
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(cmd|copy|xcopy|robocopy|powershell|pwsh|scp|winscp)\.exe$/i
| CommandLine=/(copy|xcopy|robocopy|Copy-Item|scp).*(\\\\[^\\]+\\(ADMIN\$|C\$|Windows\\Temp|Users\\Public)|\.exe|\.dll|\.ps1)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: File copy utility, remote UNC path, and executable/script extension.
* Triage Steps: Extract remote host and filename; check for service/WMI/WinRM execution next.
* Potential False Positives: Software distribution and admin maintenance.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"robocopy.exe","CommandLine":"robocopy C:\\Tools \\\\SRV2\\C$\\Windows\\Temp agent.exe"}
```

---

### [[T1550.002]] - Pass the Hash

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1550.002
> technique_name:: Pass the Hash
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Lateral_Movement

* Detection Objective: Detect lateral movement tools using NTLM hash authentication against SMB/WMI/WinRM targets.
* Telemetry Requirements: ProcessRollup2, UserLogon, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Pass-the-Hash Lateral Movement Tooling
// Focus: psexec/wmiexec/smbexec hash arguments and target hosts
#event_simpleName=ProcessRollup2
| CommandLine=/(psexec|wmiexec|smbexec|atexec|crackmapexec|netexec).*(-hashes|--hash|\/pth|aad3b435b51404eeaad3b435b51404ee|[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32})/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Hash-authentication switches paired with lateral movement tools.
* Triage Steps: Extract target, account, and hash material; review destination host service creation/logon.
* Potential False Positives: Red-team exercises and credential audits.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"crackmapexec.exe","CommandLine":"crackmapexec smb 10.0.0.5 -u admin -H 11223344556677889900aabbccddeeff"}
```

---

### [[T1210]] - Exploitation of Remote Services

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1210
> technique_name:: Exploitation of Remote Services
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Lateral_Movement

* Detection Objective: Detect exploit tooling or vulnerability-specific flags aimed at remote services from internal endpoints.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Remote Service Exploitation Tooling
// Focus: exploit scanners/tools against SMB/RDP/WinRM/Exchange/etc.
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(python|ruby|powershell|pwsh|nmap|nuclei|metasploit|msfconsole|crackmapexec|netexec)\.exe$/i
| CommandLine=/(ms17-010|zerologon|printnightmare|bluekeep|log4shell|proxyshell|proxylogon|cve-20[0-9]{2}-[0-9]{4,7}|exploit|--script\s+smb-vuln)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Exploit framework/tool names, CVEs, and remote-service exploit keywords.
* Triage Steps: Validate sanctioned testing; correlate with network fan-out and target service logs.
* Potential False Positives: Vulnerability validation by security teams.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"nmap.exe","CommandLine":"nmap --script smb-vuln-ms17-010 10.0.0.5"}
```

---

### [[T1210]] - Exploitation of Remote Services — CQL Hub: IOC search | PTC Windchill & FlexPLM vulnerability

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1210
> technique_name:: Exploitation of Remote Services
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: ioc_search_ptc_windchill_flexplm_vulnerability.yml
> cql_hub_name:: IOC search | PTC Windchill & FlexPLM vulnerability
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1210
> related_mitre_ids:: T1210
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Lateral_Movement, CQL_Hub

* Detection Objective: This query checks for Indicators of Compromise (IOCs) related to a critical Remote Code Execution vulnerability in PTC Windchill and FlexPLM. The query tracks the creation or modification of specific Java source files that an attacker may use to intercept requests, manipulate data streaming, or execute unauthorized system updates.

https://support.eacpds.com/hc/en-us/article_attachments/47430019070996

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`ioc_search_ptc_windchill_flexplm_vulnerability.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1210.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; PTC Windchill telemetry/IOCs; PTC FlexPLM telemetry/IOCs. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=/.*FileWritten/i
| (FileName=/(GW|Gen)\.class/i OR FileName=/dpr_.*\.jsp/i OR in(field=FileName, values=["Gen.java", "GW.java", "HTTPRequest.java", "HTTPResponse.java", "IXBCommonStreamer.java", "IXBStreamer.java", "MethodFeedback.java", "MethodResult.java", "WTContextUpdate.java"]))
| table([@timestamp, ComputerName, FileName, ContextBaseFileName], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This CQL query is designed to catch an attacker at two different stages of the PTC Windchill/FlexPLM exploitation lifecycle.  ### **1. The Two Detection "Stages"** The `case` block splits the search into two specific scenarios:  * **Scenario A (Active Execution/Persistence):** Looks for compiled Java files (`.class`) and web shells (`.jsp`). If these appear, the attacker has likely already triggered the exploit and is attempting to run code or maintain a backdoor. * **Scenario B (Staging/Delivery):** Looks for specific Java source files (`.java`) provided by PTC as known Indicators of Compromise. These are "payloads" that an attacker drops to overwrite core system functions.  ### **2. Key Commands Used** * **`#event_simpleName = /.*FileWritten/i`**: Monitors the exact moment a file is created or modified on the hard drive. * **`regex /.../i`**: Performs a case-insensitive search for file patterns (like the `dpr_` prefix often used for malicious web shells). * **`in(field="FileName", values=[...])`**: Efficiently checks a list of "Known Bad" filenames against your environment. * **`table`**: Displays the **Timestamp**, **Impacted Host**, and the **Specific File** involved to allow for immediate incident response.
* Key Indicators: Review query output fields and filters from `ioc_search_ptc_windchill_flexplm_vulnerability.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1550]] - Use Alternate Authentication Material — CQL Hub: ROKRAT Malware APT 37

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1550
> technique_name:: Use Alternate Authentication Material
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: ROKRAT_Malware_APT_37.yml
> cql_hub_name:: ROKRAT Malware APT 37
> cql_hub_author:: Aamir Muhammad
> related_mitre_ids:: T1550
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Lateral_Movement, CQL_Hub

* Detection Objective: RoKRAT Malware – Injection & Steganography 
🛠 High‑Level TTPs
- Initial Access: Malicious .lnk files within compressed archives. 
- Execution & Persistence: PowerShell/BAT‑driven staged loaders with XOR decryption. Defense Evasion: Process injection into trusted Windows binaries & payload concealment via steganography. 
- Command & Control: Abuse of pCloud, Yandex Disk, and Dropbox APIs with embedded tokens to blend with legitimate traffic.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`ROKRAT_Malware_APT_37.yml`), author: Aamir Muhammad.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
in(field="#event_simpleName", values=[*ProcessRollup2,DnsRequest,*Written])
|case{
    in(field="SHA256HashData", values=["3fa06c290c477c133ca58512c7852fc998632721f2dc3a0984f18fbe86451e18","ccb6ca4cb385db50dad2e3b7c68a90ddee62398edb0fd41afdb793287cfbe8e6","9eca7ab62e3ad40b79116ad713462e3ae4d9610345952e5dd279f0b481870d4f","7ee4326c5d0e6a30c1a9bdec045d670758fa1b36477992d61b03cb270113b196","e27467f7fdfa721e917384542ce10cc6108dfd78df14e23872cf8df916e0b8c6","7d514021c472e6e17f587ed30555d3f120653e6c7f8dc25d2331514b92ffd7bc","41d9b6d8cf0fff85bf35327d4b94db629cd9f754c487672911b7f701fe8c5539","6a2d984ef3fa0de9b9feb5f558381201e6dff42ef5efe4867fb24e47c6a2aade","bf7d5020dcd7777509b7b542255814cd61bfb1599d532dd2fdbb50de2ad70bc5","90bf1f20f962d04f8ae3f936d0f9046da28a75fa2fb37f267ff0453f272c60a0","ca56720610400d6da773ffa4cce5b2447d4a665087604c9c6e1c9e71c048ccfc"],ignoreCase=true);
    in(field="DomainName", values=["*api.pcloud.com","*cloud-api.yandex.net","*dropboxapi.com"], ignoreCase=true);
    (ImageFileName= /mspaint.exe/iF) |in(field="ParentBaseFileName", values=["cmd.exe","powershell.exe"], ignoreCase=true);
    (ContextBaseFileName=/mspaint.exe/iF OR ContextBaseFileName=/notepad.exe/iF) | in(field="DomainName", values=["api.dropboxapi.com","dropboxapi.com","cloud-api.yandex.net"], ignoreCase=true);
    ContextBaseFileName=/rundll32.exe/iF FileName=/version1.0.tmp/iF
}
|groupBy([ComputerName,UserName,ProcessTree,CommandLine])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: [Genians Blog - RoKRAT Shellcode and Steganographic Threats: Analysis and EDR Response Strategies](https://www.genians.co.kr/en/blog/threat_intelligence/rokrat_shellcode_steganographic)  Reference: [GitHub Aamir-Muhammad/CrowdStrike-Queries](https://github.com/Aamir-Muhammad/CrowdStrike-Queries/blob/main/Hunting-Queries/ROKRAT-Malware-APT-37.md)
* Key Indicators: Review query output fields and filters from `ROKRAT_Malware_APT_37.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1550]] - Use Alternate Authentication Material — CQL Hub: Application Consent Grant (Microsoft Entra ID)

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1550
> technique_name:: Use Alternate Authentication Material
> logscale_stream:: Other
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: application_consent_grant_microsoft_entra_id.yml
> cql_hub_name:: Application Consent Grant (Microsoft Entra ID)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1550
> related_mitre_ids:: T1550
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Lateral_Movement, CQL_Hub

* Detection Objective: Detects when a user or administrator grants consent to an application in Microsoft Entra ID, allowing it to access organizational data via delegated or application permissions. While often legitimate, this action can indicate potential abuse if a malicious application is granted excessive permissions and should be reviewed.

* Telemetry Requirements: Other
* Source: CQL Hub (`application_consent_grant_microsoft_entra_id.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1550.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on Microsoft Entra ID telemetry; Microsoft Azure telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor="microsoft"
| #event.module = azure
| #event.dataset = azure.entraid.audit
|Vendor.activityDisplayName ="Consent to application"
|table([source.user.name,source.ip,user_agent.original,user.full_name,Vendor.initiatedBy.user.displayName,"Vendor.targetResources[0].displayName",Vendor.initiatedBy.user.userPrincipalName])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects when a user or administrator grants consent to an application in Microsoft Entra ID, allowing it to access organizational data via delegated or application permissions. While often legitimate, this action can indicate potential abuse if a malicious application is granted excessive permissions and should be reviewed.
* Key Indicators: Review query output fields and filters from `application_consent_grant_microsoft_entra_id.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1550]] - Use Alternate Authentication Material — CQL Hub: Device Code Sign-In

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1550
> technique_name:: Use Alternate Authentication Material
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: device_code_sign_in.yml
> cql_hub_name:: Device Code Sign-In
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1550
> related_mitre_ids:: T1550
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Lateral_Movement, CQL_Hub

* Detection Objective: Detects authentication events using the device code flow as identified by Microsoft Defender for Identity, where a user enters a code on a separate device to complete sign‑in. While commonly used for legitimate scenarios, this method can be abused by attackers to perform phishing‑based authentication or bypass traditional sign‑in monitoring

* Telemetry Requirements: Identity
* Source: CQL Hub (`device_code_sign_in.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1550.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
|#event.dataset="defender-identity.IdentityLogonEvents"
|Vendor.properties.LogonType ="Cmsi:Cmsi"
|table([@timestamp,event.action,host.ip[0],host.os.name,host.type,user.name,Vendor.properties.AccountDisplayName,Vendor.properties.ISP])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects authentication events using the device code flow as identified by Microsoft Defender for Identity, where a user enters a code on a separate device to complete sign‑in. While commonly used for legitimate scenarios, this method can be abused by attackers to perform phishing‑based authentication or bypass traditional sign‑in monitoring
* Key Indicators: Review query output fields and filters from `device_code_sign_in.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1021]] - Remote Services — CQL Hub: Remote Interactive Logons (RDP)

> [!metadata]+ Detection Metadata
> tactic:: Lateral Movement
> technique_id:: T1021
> technique_name:: Remote Services
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: remote_interactive_logons__rdp_.yml
> cql_hub_name:: Remote Interactive Logons (RDP)
> cql_hub_author:: ByteRay
> cql_hub_mitre_ids:: T1021
> related_mitre_ids:: T1021
> required_modules:: Insight, Identity
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Lateral_Movement, CQL_Hub

* Detection Objective: Identifies remote interactive logons on a specific endpoint. The query filters UserIdentity events for LogonType=10, which typically indicates Remote Desktop or similar remote access sessions. Results are scoped by the provided aid and display up to 1,000 events, including timestamp, username, user principal, and the logon server. Useful for detecting and reviewing remote access activity during investigations or routine monitoring.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`remote_interactive_logons__rdp_.yml`), author: ByteRay.
* Original CQL Hub MITRE IDs: T1021.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight, Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=UserIdentity
| aid=?aid LogonType=10
|table([@timestamp,UserName,UserPrincipal,LogonServer],limit=1000)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: **Use Cases** - Review RDP usage on a host - Investigate potential unauthorized remote access - Support incident response and access audits  LogonType=10 corresponds to remote interactive logons. The aid parameter must be set to the target endpoint.
* Key Indicators: Review query output fields and filters from `remote_interactive_logons__rdp_.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
