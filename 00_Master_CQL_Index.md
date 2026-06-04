# CrowdStrike CQL MITRE ATT&CK Mapping Vault
## Syntax Grounding
- Primary platform: CrowdStrike Falcon SIEM / LogScale CQL.
- Grounded on current LogScale pipeline syntax: event filters, pipe-delimited stages, `select()`, regex filters, `cidr()`, `groupBy()`, `collect()`, `count()`, `in()`, and `sort()`.
- Technique names, IDs, and tactic placement are aligned to the live MITRE ATT&CK Enterprise matrix with `TA0005 - Stealth` and `TA0112 - Defense Impairment`.
- Community queries from CQL Hub are marked with `source:: CQL Hub`, preserve original source filenames, and include technology dependency notices where required modules or specific products are referenced.
- Field naming is intentionally conservative and Falcon-oriented: `ImageFileName`, `FileName`, `ParentBaseFileName`, `CommandLine`, `UserName`, `ComputerName`, `TargetFileName`, `RegObjectName`, `RegValueName`, `RemoteAddressIP4`, `RemotePort`, `DomainName`, `ContextProcessId`, `TargetProcessId`.

## Coverage Metrics

- Tactics covered: 15
- Unique ATT&CK techniques covered: 131
- Procedure sections covered: 267
- Total CQL queries: 267
- Original vault queries: 108
- CQL Hub queries: 159
- Technique entries: 267

| Tactic | Unique Techniques | Procedure Sections | Total Queries | CQL Hub Queries |
|---|---:|---:|---:|---:|
| [TA0043 - Reconnaissance](TA0043_Reconnaissance.md) | 4 | 5 | 5 | 1 |
| [TA0042 - Resource Development](TA0042_Resource_Development.md) | 5 | 5 | 5 | 0 |
| [TA0001 - Initial Access](TA0001_Initial_Access.md) | 9 | 19 | 19 | 11 |
| [TA0002 - Execution](TA0002_Execution.md) | 11 | 22 | 22 | 13 |
| [TA0003 - Persistence](TA0003_Persistence.md) | 12 | 28 | 28 | 18 |
| [TA0004 - Privilege Escalation](TA0004_Privilege_Escalation.md) | 5 | 5 | 5 | 0 |
| [TA0005 - Stealth](TA0005_Stealth.md) | 16 | 31 | 31 | 20 |
| [TA0112 - Defense Impairment](TA0112_Defense_Impairment.md) | 5 | 20 | 20 | 16 |
| [TA0006 - Credential Access](TA0006_Credential_Access.md) | 13 | 21 | 21 | 13 |
| [TA0007 - Discovery](TA0007_Discovery.md) | 13 | 38 | 38 | 29 |
| [TA0008 - Lateral Movement](TA0008_Lateral_Movement.md) | 8 | 14 | 14 | 8 |
| [TA0009 - Collection](TA0009_Collection.md) | 6 | 6 | 6 | 0 |
| [TA0011 - Command and Control](TA0011_Command_and_Control.md) | 11 | 34 | 34 | 25 |
| [TA0010 - Exfiltration](TA0010_Exfiltration.md) | 6 | 11 | 11 | 5 |
| [TA0040 - Impact](TA0040_Impact.md) | 8 | 8 | 8 | 0 |

## Global Coverage Checklist

## [[TA0043_Reconnaissance|TA0043 - Reconnaissance]]
- [ ] [[TA0043_Reconnaissance#T1595 - Active Scanning|T1595 - Active Scanning]] — Medium confidence, `NetworkConnectIP4`
- [ ] [[TA0043_Reconnaissance#T1595 - Active Scanning — CQL Hub: Systems Initiating Connections to a High Number of Ports|T1595 - Active Scanning — CQL Hub: Systems Initiating Connections to a High Number of Ports]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0043_Reconnaissance#T1592 - Gather Victim Host Information|T1592 - Gather Victim Host Information]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0043_Reconnaissance#T1590 - Gather Victim Network Information|T1590 - Gather Victim Network Information]] — Medium confidence, `DnsRequest`
- [ ] [[TA0043_Reconnaissance#T1598 - Phishing for Information|T1598 - Phishing for Information]] — Low confidence, `ProcessRollup2`

## [[TA0042_Resource_Development|TA0042 - Resource Development]]
- [ ] [[TA0042_Resource_Development#T1587 - Develop Capabilities|T1587 - Develop Capabilities]] — Low confidence, `ProcessRollup2`
- [ ] [[TA0042_Resource_Development#T1588 - Obtain Capabilities|T1588 - Obtain Capabilities]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0042_Resource_Development#T1583 - Acquire Infrastructure|T1583 - Acquire Infrastructure]] — Low confidence, `ProcessRollup2`
- [ ] [[TA0042_Resource_Development#T1584 - Compromise Infrastructure|T1584 - Compromise Infrastructure]] — Low confidence, `ProcessRollup2`
- [ ] [[TA0042_Resource_Development#T1587.001 - Malware|T1587.001 - Malware]] — Low confidence, `ProcessRollup2`

## [[TA0001_Initial_Access|TA0001 - Initial Access]]
- [ ] [[TA0001_Initial_Access#T1566.001 - Spearphishing Attachment|T1566.001 - Spearphishing Attachment]] — High confidence, `ProcessRollup2`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application|T1190 - Exploit Public-Facing Application]] — High confidence, `ProcessRollup2`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: Identify Linux Systems Vulnerable to CVE-2025-1146 with Last Logged-On User Information|T1190 - Exploit Public-Facing Application — CQL Hub: Identify Linux Systems Vulnerable to CVE-2025-1146 with Last Logged-On User Information]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using aid_master|T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using aid_master]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using OsVersionInfo|T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using OsVersionInfo]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using OsVersionInfo & Logon Data|T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-1146 - System Scoping using OsVersionInfo & Logon Data]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-53770 - SharePoint ToolShell|T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-53770 - SharePoint ToolShell]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-59287 - WSUS Identification+Vulnerability Query|T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-59287 - WSUS Identification+Vulnerability Query]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-59287 vulnerable WSUS servers identification|T1190 - Exploit Public-Facing Application — CQL Hub: CVE-2025-59287 vulnerable WSUS servers identification]] — Community confidence CQL Hub, `Endpoint, Other`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: Exploitable Critical Vulnerabilities|T1190 - Exploit Public-Facing Application — CQL Hub: Exploitable Critical Vulnerabilities]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: MongoDB Processes on Windows & Linux Hosts (CVE-2025-14847)|T1190 - Exploit Public-Facing Application — CQL Hub: MongoDB Processes on Windows & Linux Hosts (CVE-2025-14847)]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0001_Initial_Access#T1190 - Exploit Public-Facing Application — CQL Hub: Packages in Container Images - Match Lookup File|T1190 - Exploit Public-Facing Application — CQL Hub: Packages in Container Images - Match Lookup File]] — Community confidence CQL Hub, `Cloud`
- [ ] [[TA0001_Initial_Access#T1133 - External Remote Services|T1133 - External Remote Services]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0001_Initial_Access#T1189 - Drive-by Compromise|T1189 - Drive-by Compromise]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0001_Initial_Access#T1091 - Replication Through Removable Media|T1091 - Replication Through Removable Media]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0001_Initial_Access#T1078 - Valid Accounts|T1078 - Valid Accounts]] — Medium confidence, `UserLogon`
- [ ] [[TA0001_Initial_Access#T1566.002 - Spearphishing Link|T1566.002 - Spearphishing Link]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0001_Initial_Access#T1195.002 - Compromise Software Supply Chain|T1195.002 - Compromise Software Supply Chain]] — Low confidence, `ProcessRollup2`
- [ ] [[TA0001_Initial_Access#T1566 - Phishing — CQL Hub: Phishing - List of links opened from Outlook|T1566 - Phishing — CQL Hub: Phishing - List of links opened from Outlook]] — Community confidence CQL Hub, `Endpoint`

## [[TA0002_Execution|TA0002 - Execution]]
- [ ] [[TA0002_Execution#T1204.002 - Malicious File|T1204.002 - Malicious File]] — High confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1204.002 - Malicious File — CQL Hub: JAR files executed from %AppData%|T1204.002 - Malicious File — CQL Hub: JAR files executed from %AppData%]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059.001 - PowerShell|T1059.001 - PowerShell]] — High confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1059.001 - PowerShell — CQL Hub: Powershell Command Length Anomaly Detection|T1059.001 - PowerShell — CQL Hub: Powershell Command Length Anomaly Detection]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059.001 - PowerShell — CQL Hub: Suspicious PowerShell Execution|T1059.001 - PowerShell — CQL Hub: Suspicious PowerShell Execution]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059.003 - Windows Command Shell|T1059.003 - Windows Command Shell]] — High confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1059.005 - Visual Basic|T1059.005 - Visual Basic]] — High confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1059.007 - JavaScript|T1059.007 - JavaScript]] — High confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1203 - Exploitation for Client Execution|T1203 - Exploitation for Client Execution]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1559.001 - Component Object Model|T1559.001 - Component Object Model]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1129 - Shared Modules|T1129 - Shared Modules]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1047 - Windows Management Instrumentation|T1047 - Windows Management Instrumentation]] — High confidence, `ProcessRollup2`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: Detect Suspicious Windows Command-Line Activity Using System Utilities|T1059 - Command and Scripting Interpreter — CQL Hub: Detect Suspicious Windows Command-Line Activity Using System Utilities]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: Detect and Decode Base64-Encoded PowerShell Commands - http|T1059 - Command and Scripting Interpreter — CQL Hub: Detect and Decode Base64-Encoded PowerShell Commands - http]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: Detect and Decode Base64-Encoded PowerShell Commands|T1059 - Command and Scripting Interpreter — CQL Hub: Detect and Decode Base64-Encoded PowerShell Commands]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: Frequency Analysis via Program Clustering|T1059 - Command and Scripting Interpreter — CQL Hub: Frequency Analysis via Program Clustering]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: Powershell Downloads|T1059 - Command and Scripting Interpreter — CQL Hub: Powershell Downloads]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: Rare windows shell parent process|T1059 - Command and Scripting Interpreter — CQL Hub: Rare windows shell parent process]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: Applications Spawning CMD or Powershell|T1059 - Command and Scripting Interpreter — CQL Hub: Applications Spawning CMD or Powershell]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: CVE-2026-32202 - Windows Shell|T1059 - Command and Scripting Interpreter — CQL Hub: CVE-2026-32202 - Windows Shell]] — Community confidence CQL Hub, `Endpoint, Network`
- [ ] [[TA0002_Execution#T1059 - Command and Scripting Interpreter — CQL Hub: Find OpenClaw on Endpoints|T1059 - Command and Scripting Interpreter — CQL Hub: Find OpenClaw on Endpoints]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0002_Execution#T1204.001 - Malicious Link — CQL Hub: LeakNet Campaign: Deno Runtime & Klist Suspicious Execution Detection|T1204.001 - Malicious Link — CQL Hub: LeakNet Campaign: Deno Runtime & Klist Suspicious Execution Detection]] — Community confidence CQL Hub, `Endpoint`

## [[TA0003_Persistence|TA0003 - Persistence]]
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task|T1053.005 - Scheduled Task]] — High confidence, `ProcessRollup2`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find events triggered on an event|T1053.005 - Scheduled Task — CQL Hub: Find events triggered on an event]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find hidden scheduled tasks|T1053.005 - Scheduled Task — CQL Hub: Find hidden scheduled tasks]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find events triggered at logon|T1053.005 - Scheduled Task — CQL Hub: Find events triggered at logon]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find events that are scheduled|T1053.005 - Scheduled Task — CQL Hub: Find events that are scheduled]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find events triggered at startup|T1053.005 - Scheduled Task — CQL Hub: Find events triggered at startup]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find tasks scheduled by logon type|T1053.005 - Scheduled Task — CQL Hub: Find tasks scheduled by logon type]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find tasks scheduled by run level|T1053.005 - Scheduled Task — CQL Hub: Find tasks scheduled by run level]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find tasks scheduled by user ID|T1053.005 - Scheduled Task — CQL Hub: Find tasks scheduled by user ID]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find tasks scheduled with ComHandler|T1053.005 - Scheduled Task — CQL Hub: Find tasks scheduled with ComHandler]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1053.005 - Scheduled Task — CQL Hub: Find events triggered at a specific time|T1053.005 - Scheduled Task — CQL Hub: Find events triggered at a specific time]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1547.001 - Registry Run Keys / Startup Folder|T1547.001 - Registry Run Keys / Startup Folder]] — High confidence, `RegistryValueSet`
- [ ] [[TA0003_Persistence#T1543.003 - Windows Service|T1543.003 - Windows Service]] — High confidence, `ProcessRollup2`
- [ ] [[TA0003_Persistence#T1136 - Create Account|T1136 - Create Account]] — High confidence, `ProcessRollup2`
- [ ] [[TA0003_Persistence#T1505.003 - Web Shell|T1505.003 - Web Shell]] — High confidence, `ProcessRollup2`
- [ ] [[TA0003_Persistence#T1546.003 - Windows Management Instrumentation Event Subscription|T1546.003 - Windows Management Instrumentation Event Subscription]] — High confidence, `ProcessRollup2`
- [ ] [[TA0003_Persistence#T1546.008 - Accessibility Features|T1546.008 - Accessibility Features]] — High confidence, `ProcessRollup2`
- [ ] [[TA0003_Persistence#T1098 - Account Manipulation|T1098 - Account Manipulation]] — High confidence, `ProcessRollup2`
- [ ] [[TA0003_Persistence#T1098 - Account Manipulation — CQL Hub: New API Keys within the Falcon Platform|T1098 - Account Manipulation — CQL Hub: New API Keys within the Falcon Platform]] — Community confidence CQL Hub, `Other`
- [ ] [[TA0003_Persistence#T1098 - Account Manipulation — CQL Hub: Created Local User Accounts|T1098 - Account Manipulation — CQL Hub: Created Local User Accounts]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1098 - Account Manipulation — CQL Hub: Deleted Local User Accounts|T1098 - Account Manipulation — CQL Hub: Deleted Local User Accounts]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1098 - Account Manipulation — CQL Hub: Security Group Created (Microsoft Defender for Identity)|T1098 - Account Manipulation — CQL Hub: Security Group Created (Microsoft Defender for Identity)]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0003_Persistence#T1547.004 - Winlogon Helper DLL|T1547.004 - Winlogon Helper DLL]] — High confidence, `RegistryValueSet`
- [ ] [[TA0003_Persistence#T1547.009 - Shortcut Modification|T1547.009 - Shortcut Modification]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0003_Persistence#T1546 - Event Triggered Execution — CQL Hub: Detect Critical Environment Variable Changes over SSH with Connection Details|T1546 - Event Triggered Execution — CQL Hub: Detect Critical Environment Variable Changes over SSH with Connection Details]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1176 - Software Extensions — CQL Hub: Inventory of Installed Browser Extensions Across Endpoints|T1176 - Software Extensions — CQL Hub: Inventory of Installed Browser Extensions Across Endpoints]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1176 - Software Extensions — CQL Hub: Installed Browser Extensions (Aggregate by Extension)|T1176 - Software Extensions — CQL Hub: Installed Browser Extensions (Aggregate by Extension)]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0003_Persistence#T1176 - Software Extensions — CQL Hub: Installed Browser Extensions (Hunt Extension Name)|T1176 - Software Extensions — CQL Hub: Installed Browser Extensions (Hunt Extension Name)]] — Community confidence CQL Hub, `Endpoint`

## [[TA0004_Privilege_Escalation|TA0004 - Privilege Escalation]]
- [ ] [[TA0004_Privilege_Escalation#T1548 - Abuse Elevation Control Mechanism|T1548 - Abuse Elevation Control Mechanism]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0004_Privilege_Escalation#T1068 - Exploitation for Privilege Escalation|T1068 - Exploitation for Privilege Escalation]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0004_Privilege_Escalation#T1134 - Access Token Manipulation|T1134 - Access Token Manipulation]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0004_Privilege_Escalation#T1055 - Process Injection|T1055 - Process Injection]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0004_Privilege_Escalation#T1548.002 - Bypass User Account Control|T1548.002 - Bypass User Account Control]] — High confidence, `ProcessRollup2`

## [[TA0005_Stealth|TA0005 - Stealth]]
- [ ] [[TA0005_Stealth#T1218.005 - Mshta|T1218.005 - Mshta]] — High confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1218.005 - Mshta — CQL Hub: LOLBin Mshta|T1218.005 - Mshta — CQL Hub: LOLBin Mshta]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1218.011 - Rundll32|T1218.011 - Rundll32]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1218.011 - Rundll32 — CQL Hub: LOLBin Rundll32|T1218.011 - Rundll32 — CQL Hub: LOLBin Rundll32]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1574.001 - DLL (Side-Loading Procedure)|T1574.001 - DLL (Side-Loading Procedure)]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1574.001 - DLL (Search Order Hijacking Procedure)|T1574.001 - DLL (Search Order Hijacking Procedure)]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1574.001 - DLL — CQL Hub: Charon Ransomware Detection and Correlation|T1574.001 - DLL — CQL Hub: Charon Ransomware Detection and Correlation]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1574.001 - DLL — CQL Hub: Dll-Side Loading Detection Query|T1574.001 - DLL — CQL Hub: Dll-Side Loading Detection Query]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1574.001 - DLL — CQL Hub: Chromium-Based Browser Hunting via DLL Load|T1574.001 - DLL — CQL Hub: Chromium-Based Browser Hunting via DLL Load]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1574.001 - DLL — CQL Hub: Notepad++ supply chain attack|T1574.001 - DLL — CQL Hub: Notepad++ supply chain attack]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1036 - Masquerading|T1036 - Masquerading]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1027 - Obfuscated Files or Information|T1027 - Obfuscated Files or Information]] — High confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1027 - Obfuscated Files or Information — CQL Hub: JAR files written to %AppData%|T1027 - Obfuscated Files or Information — CQL Hub: JAR files written to %AppData%]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1070.004 - File Deletion|T1070.004 - File Deletion]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1070.006 - Timestomp|T1070.006 - Timestomp]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1218.010 - Regsvr32|T1218.010 - Regsvr32]] — High confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1218.010 - Regsvr32 — CQL Hub: LOLBin Regsvr32|T1218.010 - Regsvr32 — CQL Hub: LOLBin Regsvr32]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1127 - Trusted Developer Utilities Proxy Execution|T1127 - Trusted Developer Utilities Proxy Execution]] — High confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1497 - Virtualization/Sandbox Evasion|T1497 - Virtualization/Sandbox Evasion]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0005_Stealth#T1014 - Rootkit — CQL Hub: Enumerate Windows Driver Loads|T1014 - Rootkit — CQL Hub: Enumerate Windows Driver Loads]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1014 - Rootkit — CQL Hub: Check Domain Controller for NSX Driver|T1014 - Rootkit — CQL Hub: Check Domain Controller for NSX Driver]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1078 - Valid Accounts — CQL Hub: Honeytoken Account Logon Activity|T1078 - Valid Accounts — CQL Hub: Honeytoken Account Logon Activity]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0005_Stealth#T1078 - Valid Accounts — CQL Hub: Account Enabled (Microsoft Defender for Identity)|T1078 - Valid Accounts — CQL Hub: Account Enabled (Microsoft Defender for Identity)]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0005_Stealth#T1078 - Valid Accounts — CQL Hub: Active Directory Activity|T1078 - Valid Accounts — CQL Hub: Active Directory Activity]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0005_Stealth#T1078 - Valid Accounts — CQL Hub: Detection of Generic User Account Usage|T1078 - Valid Accounts — CQL Hub: Detection of Generic User Account Usage]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1078 - Valid Accounts — CQL Hub: User Logoff Activity|T1078 - Valid Accounts — CQL Hub: User Logoff Activity]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1078 - Valid Accounts — CQL Hub: User Logon Activity|T1078 - Valid Accounts — CQL Hub: User Logon Activity]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1218.007 - Msiexec — CQL Hub: LOLBin Msiexec|T1218.007 - Msiexec — CQL Hub: LOLBin Msiexec]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1218 - System Binary Proxy Execution — CQL Hub: LOLBin WMIC|T1218 - System Binary Proxy Execution — CQL Hub: LOLBin WMIC]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1197 - BITS Jobs — CQL Hub: Hunting Bitsadmin usage|T1197 - BITS Jobs — CQL Hub: Hunting Bitsadmin usage]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0005_Stealth#T1140 - Deobfuscate/Decode Files or Information — CQL Hub: InstallFix on macOS|T1140 - Deobfuscate/Decode Files or Information — CQL Hub: InstallFix on macOS]] — Community confidence CQL Hub, `Endpoint`

## [[TA0112_Defense_Impairment|TA0112 - Defense Impairment]]
- [ ] [[TA0112_Defense_Impairment#T1685.005 - Clear Windows Event Logs|T1685.005 - Clear Windows Event Logs]] — High confidence, `ProcessRollup2`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools|T1685 - Disable or Modify Tools]] — High confidence, `ProcessRollup2`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Detection of DoH traffic to known DoH-providers|T1685 - Disable or Modify Tools — CQL Hub: Detection of DoH traffic to known DoH-providers]] — Community confidence CQL Hub, `Network`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Firewall Rule Additions|T1685 - Disable or Modify Tools — CQL Hub: Firewall Rule Additions]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: GenAI Usage|T1685 - Disable or Modify Tools — CQL Hub: GenAI Usage]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Malicious Chrome Extension FreeVPN-One Detection|T1685 - Disable or Modify Tools — CQL Hub: Malicious Chrome Extension FreeVPN-One Detection]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Assigned Sensor Update Policy|T1685 - Disable or Modify Tools — CQL Hub: Assigned Sensor Update Policy]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: BYOVD Driver Load with EDR/AV Process Termination (Medusa Ransomware)|T1685 - Disable or Modify Tools — CQL Hub: BYOVD Driver Load with EDR/AV Process Termination (Medusa Ransomware)]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Calculate Next-Gen SIEM Ingestion Total|T1685 - Disable or Modify Tools — CQL Hub: Calculate Next-Gen SIEM Ingestion Total]] — Community confidence CQL Hub, `Network, Cloud, Other`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Detect locally disabled RTR|T1685 - Disable or Modify Tools — CQL Hub: Detect locally disabled RTR]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Detect RTR High Risk Commands|T1685 - Disable or Modify Tools — CQL Hub: Detect RTR High Risk Commands]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Domain Controllers with high load|T1685 - Disable or Modify Tools — CQL Hub: Domain Controllers with high load]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Hunting EDR Freeze|T1685 - Disable or Modify Tools — CQL Hub: Hunting EDR Freeze]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Packages in Container Images - Match Parameter|T1685 - Disable or Modify Tools — CQL Hub: Packages in Container Images - Match Parameter]] — Community confidence CQL Hub, `Cloud`
- [ ] [[TA0112_Defense_Impairment#T1685 - Disable or Modify Tools — CQL Hub: Recent RTR Sessions|T1685 - Disable or Modify Tools — CQL Hub: Recent RTR Sessions]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1112 - Modify Registry|T1112 - Modify Registry]] — Medium confidence, `RegistryValueSet`
- [ ] [[TA0112_Defense_Impairment#T1112 - Modify Registry — CQL Hub: Suspicious Registry Modifications|T1112 - Modify Registry — CQL Hub: Suspicious Registry Modifications]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0112_Defense_Impairment#T1222.001 - Windows Permissions|T1222.001 - Windows Permissions]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0112_Defense_Impairment#T1556 - Modify Authentication Process — CQL Hub: Account Password Not Required Changed (UAC Bypass) – Microsoft Defender for Identity|T1556 - Modify Authentication Process — CQL Hub: Account Password Not Required Changed (UAC Bypass) – Microsoft Defender for Identity]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0112_Defense_Impairment#T1556 - Modify Authentication Process — CQL Hub: Disable Strong Authentication (Microsoft Entra ID)|T1556 - Modify Authentication Process — CQL Hub: Disable Strong Authentication (Microsoft Entra ID)]] — Community confidence CQL Hub, `Other`

## [[TA0006_Credential_Access|TA0006 - Credential Access]]
- [ ] [[TA0006_Credential_Access#T1003.001 - LSASS Memory|T1003.001 - LSASS Memory]] — High confidence, `ProcessRollup2`
- [ ] [[TA0006_Credential_Access#T1003.001 - LSASS Memory — CQL Hub: Credential Dumping Detection|T1003.001 - LSASS Memory — CQL Hub: Credential Dumping Detection]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0006_Credential_Access#T1003.002 - Security Account Manager|T1003.002 - Security Account Manager]] — High confidence, `ProcessRollup2`
- [ ] [[TA0006_Credential_Access#T1555 - Credentials from Password Stores|T1555 - Credentials from Password Stores]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0006_Credential_Access#T1110 - Brute Force|T1110 - Brute Force]] — Medium confidence, `UserLogon`
- [ ] [[TA0006_Credential_Access#T1110 - Brute Force — CQL Hub: Failed User Logon Thresholding|T1110 - Brute Force — CQL Hub: Failed User Logon Thresholding]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0006_Credential_Access#T1110 - Brute Force — CQL Hub: Failed and Successful User Logon Events|T1110 - Brute Force — CQL Hub: Failed and Successful User Logon Events]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0006_Credential_Access#T1110 - Brute Force — CQL Hub: Failed logon attempt group by userName and unique Endpoint involved|T1110 - Brute Force — CQL Hub: Failed logon attempt group by userName and unique Endpoint involved]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0006_Credential_Access#T1110 - Brute Force — CQL Hub: Brute Force based on Microsoft Defender for Identity|T1110 - Brute Force — CQL Hub: Brute Force based on Microsoft Defender for Identity]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0006_Credential_Access#T1110 - Brute Force — CQL Hub: Credentials Validation Burst (Microsoft Defender for Identity)|T1110 - Brute Force — CQL Hub: Credentials Validation Burst (Microsoft Defender for Identity)]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0006_Credential_Access#T1110 - Brute Force — CQL Hub: MFA Failures|T1110 - Brute Force — CQL Hub: MFA Failures]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0006_Credential_Access#T1558.003 - Kerberoasting|T1558.003 - Kerberoasting]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0006_Credential_Access#T1552.001 - Credentials In Files|T1552.001 - Credentials In Files]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0006_Credential_Access#T1056.001 - Keylogging|T1056.001 - Keylogging]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0006_Credential_Access#T1555.003 - Credentials from Web Browsers|T1555.003 - Credentials from Web Browsers]] — High confidence, `ProcessRollup2`
- [ ] [[TA0006_Credential_Access#T1552 - Unsecured Credentials — CQL Hub: Applications with plaintext passwords|T1552 - Unsecured Credentials — CQL Hub: Applications with plaintext passwords]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0006_Credential_Access#T1003 - OS Credential Dumping — CQL Hub: Detect NTLMv1 Authentications|T1003 - OS Credential Dumping — CQL Hub: Detect NTLMv1 Authentications]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0006_Credential_Access#T1003 - OS Credential Dumping — CQL Hub: Detect NTLMv1 Authentications (Windows Event Logs)|T1003 - OS Credential Dumping — CQL Hub: Detect NTLMv1 Authentications (Windows Event Logs)]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0006_Credential_Access#T1528 - Steal Application Access Token — CQL Hub: OAuth2 Token Burst — Token Harvesting (Microsoft Defender for Identity)|T1528 - Steal Application Access Token — CQL Hub: OAuth2 Token Burst — Token Harvesting (Microsoft Defender for Identity)]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0006_Credential_Access#T1110.003 - Password Spraying — CQL Hub: Password Spray Many Users from Same IP Microsoft Defender for Identity|T1110.003 - Password Spraying — CQL Hub: Password Spray Many Users from Same IP Microsoft Defender for Identity]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0006_Credential_Access#T1003.006 - DCSync — CQL Hub: Possible DC Replication (DCSync)|T1003.006 - DCSync — CQL Hub: Possible DC Replication (DCSync)]] — Community confidence CQL Hub, `Identity`

## [[TA0007_Discovery|TA0007 - Discovery]]
- [ ] [[TA0007_Discovery#T1087.002 - Domain Account|T1087.002 - Domain Account]] — High confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1018 - Remote System Discovery|T1018 - Remote System Discovery]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1049 - System Network Connections Discovery|T1049 - System Network Connections Discovery]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery|T1082 - System Information Discovery]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Enriched Process Tree Association Events|T1082 - System Information Discovery — CQL Hub: Enriched Process Tree Association Events]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Decode SignInfoFlags|T1082 - System Information Discovery — CQL Hub: Decode SignInfoFlags]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Evaluate Operating System Prevalence|T1082 - System Information Discovery — CQL Hub: Evaluate Operating System Prevalence]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: File Write Events with Human-Readable File Sizes|T1082 - System Information Discovery — CQL Hub: File Write Events with Human-Readable File Sizes]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Remediation - Host Contained|T1082 - System Information Discovery — CQL Hub: Remediation - Host Contained]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: List of attachments sent from Outlook|T1082 - System Information Discovery — CQL Hub: List of attachments sent from Outlook]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Calculate Last Windows Boot Time|T1082 - System Information Discovery — CQL Hub: Calculate Last Windows Boot Time]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Count Windows Discovery Commands|T1082 - System Information Discovery — CQL Hub: Count Windows Discovery Commands]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Search for oldest devices|T1082 - System Information Discovery — CQL Hub: Search for oldest devices]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Falcon Sensor Heartbeat Timechart|T1082 - System Information Discovery — CQL Hub: Falcon Sensor Heartbeat Timechart]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Get Host Zero Trust Assessment Scores|T1082 - System Information Discovery — CQL Hub: Get Host Zero Trust Assessment Scores]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Hunt for specific Command Line Activity|T1082 - System Information Discovery — CQL Hub: Hunt for specific Command Line Activity]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Hunt for a file name|T1082 - System Information Discovery — CQL Hub: Hunt for a file name]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: List all Identity Protection Detections|T1082 - System Information Discovery — CQL Hub: List all Identity Protection Detections]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: OS Platform ratio|T1082 - System Information Discovery — CQL Hub: OS Platform ratio]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Find processes that only ran a few of times on a specific host|T1082 - System Information Discovery — CQL Hub: Find processes that only ran a few of times on a specific host]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: Devices in RFM state|T1082 - System Information Discovery — CQL Hub: Devices in RFM state]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1082 - System Information Discovery — CQL Hub: User Logon Details (Time, Type, Location, Last Password Change)|T1082 - System Information Discovery — CQL Hub: User Logon Details (Time, Type, Location, Last Password Change)]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1057 - Process Discovery|T1057 - Process Discovery]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1482 - Domain Trust Discovery|T1482 - Domain Trust Discovery]] — High confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1135 - Network Share Discovery|T1135 - Network Share Discovery]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1135 - Network Share Discovery — CQL Hub: SMB Enumeration | Defender for Identity|T1135 - Network Share Discovery — CQL Hub: SMB Enumeration | Defender for Identity]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0007_Discovery#T1135 - Network Share Discovery — CQL Hub: Users creating Network Shares|T1135 - Network Share Discovery — CQL Hub: Users creating Network Shares]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1518.001 - Security Software Discovery|T1518.001 - Security Software Discovery]] — High confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1124 - System Time Discovery|T1124 - System Time Discovery]] — Low confidence, `ProcessRollup2`
- [ ] [[TA0007_Discovery#T1046 - Network Service Discovery — CQL Hub: Rare Remote Ports in Network Connections|T1046 - Network Service Discovery — CQL Hub: Rare Remote Ports in Network Connections]] — Community confidence CQL Hub, `Endpoint, Network`
- [ ] [[TA0007_Discovery#T1046 - Network Service Discovery — CQL Hub: External Connectons with Process|T1046 - Network Service Discovery — CQL Hub: External Connectons with Process]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1046 - Network Service Discovery — CQL Hub: Falcon Sensor Support Status|T1046 - Network Service Discovery — CQL Hub: Falcon Sensor Support Status]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1069.002 - Domain Groups — CQL Hub: Domain Admin Enumeration|T1069.002 - Domain Groups — CQL Hub: Domain Admin Enumeration]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0007_Discovery#T1526 - Cloud Service Discovery — CQL Hub: Identify Shadow SaaS|T1526 - Cloud Service Discovery — CQL Hub: Identify Shadow SaaS]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0007_Discovery#T1526 - Cloud Service Discovery — CQL Hub: Identity Protection - Average Cloud Response Time|T1526 - Cloud Service Discovery — CQL Hub: Identity Protection - Average Cloud Response Time]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0007_Discovery#T1087 - Account Discovery — CQL Hub: LDAP Enumeration|T1087 - Account Discovery — CQL Hub: LDAP Enumeration]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0007_Discovery#T1087 - Account Discovery — CQL Hub: SAMR Burst (BloodHound/PowerView)|T1087 - Account Discovery — CQL Hub: SAMR Burst (BloodHound/PowerView)]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0007_Discovery#T1087 - Account Discovery — CQL Hub: Windows authentication traffic metrics|T1087 - Account Discovery — CQL Hub: Windows authentication traffic metrics]] — Community confidence CQL Hub, `Identity`

## [[TA0008_Lateral_Movement|TA0008 - Lateral Movement]]
- [ ] [[TA0008_Lateral_Movement#T1021.002 - SMB/Windows Admin Shares|T1021.002 - SMB/Windows Admin Shares]] — High confidence, `ProcessRollup2`
- [ ] [[TA0008_Lateral_Movement#T1021.002 - SMB/Windows Admin Shares — CQL Hub: SMB File Copy to Multiple Devices (Microsoft Defender for Identity)|T1021.002 - SMB/Windows Admin Shares — CQL Hub: SMB File Copy to Multiple Devices (Microsoft Defender for Identity)]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0008_Lateral_Movement#T1021.006 - Windows Remote Management|T1021.006 - Windows Remote Management]] — High confidence, `ProcessRollup2`
- [ ] [[TA0008_Lateral_Movement#T1021.001 - Remote Desktop Protocol|T1021.001 - Remote Desktop Protocol]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0008_Lateral_Movement#T1021.001 - Remote Desktop Protocol — CQL Hub: Lateral Movement Detection|T1021.001 - Remote Desktop Protocol — CQL Hub: Lateral Movement Detection]] — Community confidence CQL Hub, `Network`
- [ ] [[TA0008_Lateral_Movement#T1021.001 - Remote Desktop Protocol — CQL Hub: Potential Lateral Movement through RDP|T1021.001 - Remote Desktop Protocol — CQL Hub: Potential Lateral Movement through RDP]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0008_Lateral_Movement#T1570 - Lateral Tool Transfer|T1570 - Lateral Tool Transfer]] — High confidence, `ProcessRollup2`
- [ ] [[TA0008_Lateral_Movement#T1550.002 - Pass the Hash|T1550.002 - Pass the Hash]] — High confidence, `ProcessRollup2`
- [ ] [[TA0008_Lateral_Movement#T1210 - Exploitation of Remote Services|T1210 - Exploitation of Remote Services]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0008_Lateral_Movement#T1210 - Exploitation of Remote Services — CQL Hub: IOC search | PTC Windchill & FlexPLM vulnerability|T1210 - Exploitation of Remote Services — CQL Hub: IOC search | PTC Windchill & FlexPLM vulnerability]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0008_Lateral_Movement#T1550 - Use Alternate Authentication Material — CQL Hub: ROKRAT Malware APT 37|T1550 - Use Alternate Authentication Material — CQL Hub: ROKRAT Malware APT 37]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0008_Lateral_Movement#T1550 - Use Alternate Authentication Material — CQL Hub: Application Consent Grant (Microsoft Entra ID)|T1550 - Use Alternate Authentication Material — CQL Hub: Application Consent Grant (Microsoft Entra ID)]] — Community confidence CQL Hub, `Other`
- [ ] [[TA0008_Lateral_Movement#T1550 - Use Alternate Authentication Material — CQL Hub: Device Code Sign-In|T1550 - Use Alternate Authentication Material — CQL Hub: Device Code Sign-In]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0008_Lateral_Movement#T1021 - Remote Services — CQL Hub: Remote Interactive Logons (RDP)|T1021 - Remote Services — CQL Hub: Remote Interactive Logons (RDP)]] — Community confidence CQL Hub, `Endpoint`

## [[TA0009_Collection|TA0009 - Collection]]
- [ ] [[TA0009_Collection#T1005 - Data from Local System|T1005 - Data from Local System]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0009_Collection#T1113 - Screen Capture|T1113 - Screen Capture]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0009_Collection#T1560 - Archive Collected Data|T1560 - Archive Collected Data]] — High confidence, `ProcessRollup2`
- [ ] [[TA0009_Collection#T1119 - Automated Collection|T1119 - Automated Collection]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0009_Collection#T1115 - Clipboard Data|T1115 - Clipboard Data]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0009_Collection#T1213 - Data from Information Repositories|T1213 - Data from Information Repositories]] — Medium confidence, `ProcessRollup2`

## [[TA0011_Command_and_Control|TA0011 - Command and Control]]
- [ ] [[TA0011_Command_and_Control#T1071.004 - DNS|T1071.004 - DNS]] — Medium confidence, `DnsRequest`
- [ ] [[TA0011_Command_and_Control#T1071.004 - DNS — CQL Hub: DNS Resolutions from Browser Processes|T1071.004 - DNS — CQL Hub: DNS Resolutions from Browser Processes]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1071.004 - DNS — CQL Hub: Detection of DNS Requests to AI-Related Domains|T1071.004 - DNS — CQL Hub: Detection of DNS Requests to AI-Related Domains]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1071.004 - DNS — CQL Hub: DNS Staging Detection: ClickFix-Inspired nslookup Execution|T1071.004 - DNS — CQL Hub: DNS Staging Detection: ClickFix-Inspired nslookup Execution]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1105 - Ingress Tool Transfer|T1105 - Ingress Tool Transfer]] — High confidence, `ProcessRollup2`
- [ ] [[TA0011_Command_and_Control#T1105 - Ingress Tool Transfer — CQL Hub: Detection of External Direct IP Usage in CommandLine Windows and Mac|T1105 - Ingress Tool Transfer — CQL Hub: Detection of External Direct IP Usage in CommandLine Windows and Mac]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1105 - Ingress Tool Transfer — CQL Hub: LOLBin Certutil|T1105 - Ingress Tool Transfer — CQL Hub: LOLBin Certutil]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1571 - Non-Standard Port|T1571 - Non-Standard Port]] — Medium confidence, `NetworkConnectIP4`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy|T1090 - Proxy]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Files Written to Removable Media|T1090 - Proxy — CQL Hub: Files Written to Removable Media]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Impossible Travel Time Azure|T1090 - Proxy — CQL Hub: Impossible Travel Time Azure]] — Community confidence CQL Hub, `Network, Identity`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: AWS S3 Bucket Policy Updates|T1090 - Proxy — CQL Hub: AWS S3 Bucket Policy Updates]] — Community confidence CQL Hub, `Cloud`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Cloud Credential Violation IOMs|T1090 - Proxy — CQL Hub: Cloud Credential Violation IOMs]] — Community confidence CQL Hub, `Cloud`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Cloud Data Exfiltration IOMs|T1090 - Proxy — CQL Hub: Cloud Data Exfiltration IOMs]] — Community confidence CQL Hub, `Cloud`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Cloud Least Privilege IOMs|T1090 - Proxy — CQL Hub: Cloud Least Privilege IOMs]] — Community confidence CQL Hub, `Cloud`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Cloud MFA Violation IOMs|T1090 - Proxy — CQL Hub: Cloud MFA Violation IOMs]] — Community confidence CQL Hub, `Cloud`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (Windows)|T1090 - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (Windows)]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (Linux)|T1090 - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (Linux)]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (MacOS)|T1090 - Proxy — CQL Hub: Falcon Sensor Version Drift Monitoring (MacOS)]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Inspected LDAP / Kerberos / DCE/RCP Traffic|T1090 - Proxy — CQL Hub: Inspected LDAP / Kerberos / DCE/RCP Traffic]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: MFA Status Monitoring|T1090 - Proxy — CQL Hub: MFA Status Monitoring]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: New installed Sensors|T1090 - Proxy — CQL Hub: New installed Sensors]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Sensor Version Adoption Trend|T1090 - Proxy — CQL Hub: Sensor Version Adoption Trend]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: SOC Efficiency Metrics|T1090 - Proxy — CQL Hub: SOC Efficiency Metrics]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Torrent Website Access Detected|T1090 - Proxy — CQL Hub: Torrent Website Access Detected]] — Community confidence CQL Hub, `Network`
- [ ] [[TA0011_Command_and_Control#T1090 - Proxy — CQL Hub: Windows Store Installs|T1090 - Proxy — CQL Hub: Windows Store Installs]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1572 - Protocol Tunneling|T1572 - Protocol Tunneling]] — Medium confidence, `NetworkConnectIP4`
- [ ] [[TA0011_Command_and_Control#T1572 - Protocol Tunneling — CQL Hub: Remote Port Forwarding via Plink - Unauthorized RDP Tunneling Detection|T1572 - Protocol Tunneling — CQL Hub: Remote Port Forwarding via Plink - Unauthorized RDP Tunneling Detection]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1102 - Web Service|T1102 - Web Service]] — Medium confidence, `DnsRequest`
- [ ] [[TA0011_Command_and_Control#T1001 - Data Obfuscation|T1001 - Data Obfuscation]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0011_Command_and_Control#T1573 - Encrypted Channel|T1573 - Encrypted Channel]] — Low confidence, `ProcessRollup2`
- [ ] [[TA0011_Command_and_Control#T1095 - Non-Application Layer Protocol|T1095 - Non-Application Layer Protocol]] — Medium confidence, `NetworkConnectIP4`
- [ ] [[TA0011_Command_and_Control#T1090.003 - Multi-hop Proxy — CQL Hub: Connections to Tor Exit Nodes|T1090.003 - Multi-hop Proxy — CQL Hub: Connections to Tor Exit Nodes]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0011_Command_and_Control#T1219.002 - Remote Desktop Software — CQL Hub: Detect Remote Monitoring and Management (RMM) Tools over DNS|T1219.002 - Remote Desktop Software — CQL Hub: Detect Remote Monitoring and Management (RMM) Tools over DNS]] — Community confidence CQL Hub, `Network`

## [[TA0010_Exfiltration|TA0010 - Exfiltration]]
- [ ] [[TA0010_Exfiltration#T1041 - Exfiltration Over C2 Channel|T1041 - Exfiltration Over C2 Channel]] — Medium confidence, `NetworkConnectIP4`
- [ ] [[TA0010_Exfiltration#T1567.002 - Exfiltration to Cloud Storage|T1567.002 - Exfiltration to Cloud Storage]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0010_Exfiltration#T1048 - Exfiltration Over Alternative Protocol|T1048 - Exfiltration Over Alternative Protocol]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0010_Exfiltration#T1048 - Exfiltration Over Alternative Protocol — CQL Hub: High Volume SMB File Copy (Data Exfiltration / Ransomware) – Microsoft Defender for Identity|T1048 - Exfiltration Over Alternative Protocol — CQL Hub: High Volume SMB File Copy (Data Exfiltration / Ransomware) – Microsoft Defender for Identity]] — Community confidence CQL Hub, `Identity`
- [ ] [[TA0010_Exfiltration#T1048 - Exfiltration Over Alternative Protocol — CQL Hub: Snowman|T1048 - Exfiltration Over Alternative Protocol — CQL Hub: Snowman]] — Community confidence CQL Hub, `Unknown`
- [ ] [[TA0010_Exfiltration#T1020 - Automated Exfiltration|T1020 - Automated Exfiltration]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0010_Exfiltration#T1030 - Data Transfer Size Limits|T1030 - Data Transfer Size Limits]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0010_Exfiltration#T1052 - Exfiltration Over Physical Medium|T1052 - Exfiltration Over Physical Medium]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0010_Exfiltration#T1052 - Exfiltration Over Physical Medium — CQL Hub: Decode VolumeDeviceCharacteristics Bitmask|T1052 - Exfiltration Over Physical Medium — CQL Hub: Decode VolumeDeviceCharacteristics Bitmask]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0010_Exfiltration#T1052 - Exfiltration Over Physical Medium — CQL Hub: Detect Data Exfiltration via external storage devices|T1052 - Exfiltration Over Physical Medium — CQL Hub: Detect Data Exfiltration via external storage devices]] — Community confidence CQL Hub, `Endpoint`
- [ ] [[TA0010_Exfiltration#T1052 - Exfiltration Over Physical Medium — CQL Hub: Get USB Devices|T1052 - Exfiltration Over Physical Medium — CQL Hub: Get USB Devices]] — Community confidence CQL Hub, `Endpoint`

## [[TA0040_Impact|TA0040 - Impact]]
- [ ] [[TA0040_Impact#T1486 - Data Encrypted for Impact|T1486 - Data Encrypted for Impact]] — High confidence, `ProcessRollup2`
- [ ] [[TA0040_Impact#T1490 - Inhibit System Recovery|T1490 - Inhibit System Recovery]] — High confidence, `ProcessRollup2`
- [ ] [[TA0040_Impact#T1489 - Service Stop|T1489 - Service Stop]] — High confidence, `ProcessRollup2`
- [ ] [[TA0040_Impact#T1485 - Data Destruction|T1485 - Data Destruction]] — High confidence, `ProcessRollup2`
- [ ] [[TA0040_Impact#T1531 - Account Access Removal|T1531 - Account Access Removal]] — High confidence, `ProcessRollup2`
- [ ] [[TA0040_Impact#T1565.001 - Stored Data Manipulation|T1565.001 - Stored Data Manipulation]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0040_Impact#T1491.001 - Internal Defacement|T1491.001 - Internal Defacement]] — Medium confidence, `ProcessRollup2`
- [ ] [[TA0040_Impact#T1499 - Endpoint Denial of Service|T1499 - Endpoint Denial of Service]] — Medium confidence, `ProcessRollup2`

## Maintenance Notes

- Prefer behavior-first detections: parent/child process anomalies, execution location, grouped network behavior, registry/service modification context, and DNS/network aggregation.
- Treat these as production-ready hunting seeds: validate field availability and tune local allowlists before alert promotion.
- For CQL Hub additions, review `required_modules`, `logscale_stream`, and technology dependency notices before promoting to scheduled searches or detections.
- When adding a new query, add it to the tactic file using the same YAML + CQL + analytical breakdown schema, then regenerate this checklist.
