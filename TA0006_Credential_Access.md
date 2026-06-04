# TA0006 - Credential Access

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Credential Access. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1003.001]] - LSASS Memory

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1003.001
> technique_name:: LSASS Memory
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Credential_Access

* Detection Objective: Detect LSASS dumping using procdump, rundll32 comsvcs.dll MiniDump, taskmgr, or suspicious dump file arguments.
* Telemetry Requirements: ProcessRollup2, ImageHash

#### Production-Ready CQL Query:

```cql
// Title: LSASS Dump via Procdump or Comsvcs MiniDump
// Focus: Process dumping tools targeting lsass.exe
#event_simpleName=ProcessRollup2
| CommandLine=/(lsass|comsvcs\.dll|MiniDump|procdump|rundll32.+comsvcs|taskmgr.+dump|\.dmp)/i
| ImageFileName=/\\(procdump|procdump64|rundll32|taskmgr|werfault|powershell|cmd)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Dump utility or comsvcs MiniDump invocation targeting lsass or producing .dmp output.
* Triage Steps: Isolate host, collect dump path if present, verify credential exposure, and rotate affected secrets.
* Potential False Positives: Approved memory diagnostics by IR teams; should be rare and ticketed.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"rundll32.exe","CommandLine":"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Temp\\lsass.dmp full"}
```

---

### [[T1003.001]] - LSASS Memory — CQL Hub: Credential Dumping Detection

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1003.001
> technique_name:: LSASS Memory
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Credential_Dumping_Detection.yml
> cql_hub_name:: Credential Dumping Detection
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1003.001, T1003.002, T1558.003
> related_mitre_ids:: T1003.001, T1003.002, T1558.003
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: This query detects potential credential dumping activities by monitoring process access to LSASS and suspicious memory operations.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Credential_Dumping_Detection.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1003.001, T1003.002, T1558.003.
* Related/Resolved MITRE IDs: T1003.001, T1003.002, T1558.003.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2
| (CommandLine=/(mimikatz|procdump|lsass|sekurlsa)/i OR ImageFileName=/\\(mimikatz|procdump|procdump64|pwdump|rundll32|taskmgr)\.exe$/i)
| !ParentImageFileName=/\\(powershell|cmd)\.exe$/i
| table([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName, SHA256HashData], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This query uses CrowdStrike Query Language (CQL) to detect credential dumping activities:  1. **Process Monitoring**: `#event_simpleName=ProcessRollup2`    - Monitors process execution events across endpoints  2. **Suspicious Indicators**: `(CommandLine=/mimikatz|procdump|lsass|sekurlsa/i OR ImageFileName=/\\(mimikatz|procdump|pwdump)\.exe$/i)`    - Detects known credential dumping tools and LSASS access patterns  3. **Parent Process Filter**: `ParentImageFileName!=/\\(powershell|cmd)\.exe$/i`    - Excludes common legitimate parent processes to reduce noise  4. **User Context**: `join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])`    - Adds user account information for attribution  5. **Process Hash**: `join({#event_simpleName=SyntheticProcessRollup2}, field=[aid, RawProcessId], include=[SHA256HashData], suffix="Parent")`    - Includes file hash for threat intelligence correlation  6. **Output**: `table([aid, UserName, ImageFileName, CommandLine, ParentImageFileName, SHA256HashData])`    - Displays process details, user context, and file hash information
* Key Indicators: Review query output fields and filters from `Credential_Dumping_Detection.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1003.002]] - Security Account Manager

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1003.002
> technique_name:: Security Account Manager
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Credential_Access

* Detection Objective: Detect registry hive exports of SAM, SYSTEM, or SECURITY, a common offline credential dumping precursor.
* Telemetry Requirements: ProcessRollup2, RegistryValueSet

#### Production-Ready CQL Query:

```cql
// Title: SAM SYSTEM SECURITY Hive Export
// Focus: reg save/export of credential-bearing hives
#event_simpleName=ProcessRollup2
| ImageFileName=/\\reg\.exe$/i
| CommandLine=/(save|export).*(HKLM\\SAM|HKLM\\SYSTEM|HKLM\\SECURITY|hklm\\sam|hklm\\system|hklm\\security)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Direct export/save of credential-bearing registry hives.
* Triage Steps: Check output file path and file transfer events; assume local credential material may be compromised.
* Potential False Positives: Backup tooling or forensic acquisition under change control.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"reg.exe","CommandLine":"reg save HKLM\\\\SAM C:\\Users\\Public\\sam.save"}
```

---

### [[T1555]] - Credentials from Password Stores

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1555
> technique_name:: Credentials from Password Stores
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Credential_Access

* Detection Objective: Detect suspicious access to browser credential stores, Windows Credential Manager, or DPAPI material by shells/scripts.
* Telemetry Requirements: ProcessRollup2, FileOpenInfo

#### Production-Ready CQL Query:

```cql
// Title: Browser and DPAPI Credential Store Access
// Focus: Script or CLI access to Login Data, Web Data, Vault, or DPAPI paths
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|cmd|python|sqlite3|rundll32)\.exe$/i
| CommandLine=/(Login Data|Web Data|Cookies|Local State|\\Microsoft\\Vault\\|\\Protect\\|dpapi|CryptUnprotectData|vaultcmd)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Credential-store path tokens or DPAPI/Credential Manager tooling in command line.
* Triage Steps: Identify files touched and whether data was copied or exfiltrated; correlate with [[T1041]] or [[T1105]].
* Potential False Positives: Browser migration tools and enterprise password backup utilities.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"python.exe","CommandLine":"python dump.py C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"}
```

---

### [[T1110]] - Brute Force

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1110
> technique_name:: Brute Force
> logscale_stream:: UserLogon
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Credential_Access

* Detection Objective: Detect repeated failed logons or authentication attempts grouped by host/user/source context.
* Telemetry Requirements: UserLogon, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Repeated Authentication Failure Burst
// Focus: Many failed logons for same user or host
#event_simpleName=UserLogonFailed
| UserName=*
| groupBy([ComputerName, UserName, RemoteAddressIP4], function=[count(as=failure_count), collect(LogonType, limit=10)])
| failure_count >= 10
| sort(failure_count, order=desc)
| select([ComputerName, UserName, RemoteAddressIP4, failure_count, LogonType])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: High failure count for a user/source pair.
* Triage Steps: Check for subsequent successful logon and source IP ownership; enforce password reset/MFA as needed.
* Potential False Positives: Password changes, misconfigured services, vulnerability scanners.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"UserLogonFailed","UserName":"alice","RemoteAddressIP4":"203.0.113.10","ComputerName":"SRV1"}
```

---

### [[T1110]] - Brute Force — CQL Hub: Failed User Logon Thresholding

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1110
> technique_name:: Brute Force
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Failed_User_Logon_Thresholding.yml
> cql_hub_name:: Failed User Logon Thresholding
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1110
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: This query identifies Windows failed login attempts that exceed a threshold (5+ failures), helping detect potential brute force attacks or account compromise attempts
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Failed_User_Logon_Thresholding.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get Windows UserLogonFailed events.
#event_simpleName=UserLogonFailed2
| event_platform=Win

// Convert SubStatus to hex.
| SubStatus_hex := format(field=SubStatus, "%x")
| SubStatus_hex := upper(SubStatus_hex)
| SubStatus_hex := format(format="0x%s", field=[SubStatus_hex])

// Aggregate results and calculate rate.
| groupBy([aid, ComputerName, UserName, LogonType, SubStatus_hex, SubStatus], function=[count(as=FailCount), min(ContextTimeStamp, as=FirstLogonAttempt), max(ContextTimeStamp, as=LastLogonAttempt), collect([LocalAddressIP4, aip], limit=25)], limit=20000)
| firstLastDeltaHours := (LastLogonAttempt - FirstLogonAttempt) / 60 / 60
| firstLastDeltaHours > 0
| logonAttemptsPerHour := FailCount / firstLastDeltaHours

// Convert timestamps from epoch to human-readable UTC.
| FirstLogonAttempt := formatTime(format="%F %T.%L", field=FirstLogonAttempt, timezone="UTC")
| LastLogonAttempt := formatTime(format="%F %T.%L", field=LastLogonAttempt, timezone="UTC")

// Threshold for failed logins.
| FailCount > 5
| sort(FailCount, order=desc, limit=2000)
| $falcon/helper:enrich(field=LogonType)
| $falcon/helper:enrich(field=SubStatus)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Failed_User_Logon_Thresholding.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1110]] - Brute Force — CQL Hub: Failed and Successful User Logon Events

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1110
> technique_name:: Brute Force
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Failed_and_Successful_User_Logon_Events.yml
> cql_hub_name:: Failed and Successful User Logon Events
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1110
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: This query correlates successful and failed logon attempts per user account to identify potential compromise patterns, focusing on accounts with 4+ failed logons. It provides a comprehensive view of each user's authentication activity including password age and last successful access.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Failed_and_Successful_User_Logon_Events.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=/^UserLogon(Failed2)?$/
| case {
    #event_simpleName=UserLogon | SuccessLogonTime := ContextTimeStamp;
    #event_simpleName=UserLogonFailed2 | FailedLogonTime := ContextTimeStamp;
}
| groupBy([UserSid, UserName], function=[min(FailedLogonTime, as=FirstFailedLogon), max(FailedLogonTime, as=LastFailedLogon), max(SuccessLogonTime, as=LastSuccessfulLogin), count(SuccessLogonTime, as=TotalSuccessfulLogins), count(FailedLogonTime, as=TotalFailedLogins), collect(ComputerName, limit=10)], limit=20000)
| TotalFailedLogins > 3
| formatTime(format="%F %T", field=FirstFailedLogon, as=FirstFailedLogon, timezone="UTC")
| formatTime(format="%F %T", field=LastFailedLogon, as=LastFailedLogon, timezone="UTC")
| formatTime(format="%F %T", field=LastSuccessfulLogin, as=LastSuccessfulLogin, timezone="UTC")
| default(value="-", field=[FirstFailedLogon, LastFailedLogon, LastSuccessfulLogin, TotalSuccessfulLogins, TotalFailedLogins])
| sort(TotalFailedLogins, order=desc, limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Failed_and_Successful_User_Logon_Events.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1110]] - Brute Force — CQL Hub: Failed logon attempt group by userName and unique Endpoint involved

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1110
> technique_name:: Brute Force
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Failed_logon_attempt.yml
> cql_hub_name:: Failed logon attempt group by userName and unique Endpoint involved
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1110
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: Community-contributed CQL Hub query mapped to this ATT&CK technique.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Failed_logon_attempt.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName = UserLogonFailed
| groupBy(UserName, function=([count(timestamp, distinct=true, as=uniqueFailedLogons), (count(aid, distinct=true, as=uniqueEP)), collect(fields = [ComputerName, aid], limit =10000)]))
| default(field = "UserName", value="-", replaceEmpty=true)
| uniqueFailedLogons >= 5
| uniqueEP >= 10
| sort(uniqueEP)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Failed_logon_attempt.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1110]] - Brute Force — CQL Hub: Brute Force based on Microsoft Defender for Identity

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1110
> technique_name:: Brute Force
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: brute_force_based_on_microsoft_defender_for_identity.yml
> cql_hub_name:: Brute Force based on Microsoft Defender for Identity
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1110
> related_mitre_ids:: T1110
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: Detects multiple failed authentication attempts against a user account as identified by Microsoft Defender for Identity. This behavior may indicate brute‑force or password‑guessing activity aimed at compromising credentials and gaining unauthorized access

* Telemetry Requirements: Identity
* Source: CQL Hub (`brute_force_based_on_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1110.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityLogonEvents"
| Vendor.properties.LogonType = "Failed logon"
| groupBy([user.name, source.address], function=[count(as=failed_logons),count(field=Vendor.properties.DestinationDeviceName, distinct=true, as=unique_destinations),collect(fields=Vendor.properties.DestinationDeviceName),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| failed_logons >=5 //Adjust the value 
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 10 //Adjust the value 
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([failed_logons], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects multiple failed authentication attempts against a user account as identified by Microsoft Defender for Identity. This behavior may indicate brute‑force or password‑guessing activity aimed at compromising credentials and gaining unauthorized access
* Key Indicators: Review query output fields and filters from `brute_force_based_on_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1110]] - Brute Force — CQL Hub: Credentials Validation Burst (Microsoft Defender for Identity)

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1110
> technique_name:: Brute Force
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: credentials_validation_burst_microsoft_defender_for_identity.yml
> cql_hub_name:: Credentials Validation Burst (Microsoft Defender for Identity)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1110
> related_mitre_ids:: T1110
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: Detects a high volume of authentication or credential validation attempts against Active Directory accounts within a short timeframe. This behavior is commonly associated with automated credential‑testing activity such as password spraying or brute‑force attempts and should be investigated.

* Telemetry Requirements: Identity
* Source: CQL Hub (`credentials_validation_burst_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1110.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityLogonEvents"
| Vendor.properties.LogonType = "Credentials validation"
| groupBy([user.name, source.address], function=[count(as=validation_count),count(field=Vendor.properties.DestinationDeviceName, distinct=true, as=unique_destinations),collect(fields=Vendor.properties.DestinationDeviceName),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| validation_count > 50 //Adjust the value as per your enviorment
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 10 //Adjust the value as per your enviorment
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([validation_count], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects a high volume of authentication or credential validation attempts against Active Directory accounts within a short timeframe. This behavior is commonly associated with automated credential‑testing activity such as password spraying or brute‑force attempts and should be investigated.
* Key Indicators: Review query output fields and filters from `credentials_validation_burst_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1110]] - Brute Force — CQL Hub: MFA Failures

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1110
> technique_name:: Brute Force
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: mfa_failures.yml
> cql_hub_name:: MFA Failures
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1110
> required_modules:: Identity
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: Displays the count of MFA authentication failures caused by service errors or user not being enrolled. A sudden spike in these errors may indicate a service incident requiring immediate investigation and response.
* Telemetry Requirements: Identity
* Source: CQL Hub (`mfa_failures.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo=base_sensor #event_simpleName=IdpPolicy*RuleMatch
| in(field=cid, values=[?SelectedCid])
| match(file="aid_master_main.csv", field=[cid, aid])
// Filters
| in(field=MachineDomain, values=[?SelectedDomain])
| case {
  IdpPolicyMfaStatus=128 | MfaError:="User Not Enrolled";
  IdpPolicyMfaStatus=256 | MfaError:="Service Error";
  *;
}
| timeChart(series=MfaError)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `mfa_failures.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1558.003]] - Kerberoasting

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1558.003
> technique_name:: Kerberoasting
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Credential_Access

* Detection Objective: Detect Kerberoasting tool usage and LDAP/SPN enumeration commands.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Kerberoasting SPN Enumeration and Ticket Request Tooling
// Focus: setspn/GetUserSPNs/Rubeus kerberoast patterns
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(setspn|powershell|pwsh|rubeus|cmd)\.exe$/i
| CommandLine=/(setspn\s+-Q|servicePrincipalName|GetUserSPNs|kerberoast|asreproast|Rubeus.+kerberoast|Invoke-Kerberoast)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: SPN enumeration and Kerberoast tool/verb names.
* Triage Steps: Validate admin purpose; inspect generated ticket files and follow-on cracking/exfil.
* Potential False Positives: Identity admin audits and red-team tests.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"setspn.exe","CommandLine":"setspn -Q */*"}
```

---

### [[T1552.001]] - Credentials In Files

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1552.001
> technique_name:: Credentials In Files
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Credential_Access

* Detection Objective: Detect command-line searches for passwords, keys, tokens, or config secrets across user and application directories.
* Telemetry Requirements: ProcessRollup2, FileOpenInfo

#### Production-Ready CQL Query:

```cql
// Title: Credential String Search in Files
// Focus: findstr/select-string/grep searches for secrets
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(findstr|powershell|pwsh|cmd|grep|python)\.exe$/i
| CommandLine=/(password|passwd|pwd|secret|token|apikey|api_key|client_secret|connectionstring|private_key|BEGIN RSA PRIVATE KEY)/i
| CommandLine=/(findstr|Select-String|grep|Get-ChildItem|dir\s+\/s)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Search tools plus credential keywords.
* Triage Steps: Identify searched paths and copied results; rotate exposed secrets if confirmed.
* Potential False Positives: Developers/admins troubleshooting configs.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"findstr.exe","CommandLine":"findstr /si password *.config *.xml *.txt"}
```

---

### [[T1056.001]] - Keylogging

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1056.001
> technique_name:: Keylogging
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Credential_Access

* Detection Objective: Detect keylogging API usage or suspicious utilities referencing keyboard hooks.
* Telemetry Requirements: ProcessRollup2, ImageLoad

#### Production-Ready CQL Query:

```cql
// Title: Keyboard Hook or Keylogger Indicator
// Focus: SetWindowsHookEx/GetAsyncKeyState/GetKeyState tokens
#event_simpleName=ProcessRollup2
| CommandLine=/(SetWindowsHookEx|GetAsyncKeyState|GetKeyState|keylog|keyboard hook|WH_KEYBOARD_LL|pynput|GetKeyboardState)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Keyboard-hook API names and keylogger terminology.
* Triage Steps: Validate binary and parent process; inspect persistence and outbound channels.
* Potential False Positives: Accessibility tools, hotkey utilities, security testing.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"python.exe","CommandLine":"python keylogger.py --api GetAsyncKeyState"}
```

---

### [[T1555.003]] - Credentials from Web Browsers

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1555.003
> technique_name:: Credentials from Web Browsers
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Credential_Access

* Detection Objective: Detect command-line access to browser credential databases and local state files.
* Telemetry Requirements: ProcessRollup2, FileOpenInfo

#### Production-Ready CQL Query:

```cql
// Title: Browser Credential Database Access
// Focus: Chrome/Edge/Firefox Login Data, Cookies, Local State collection
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|cmd|python|sqlite3|copy|xcopy|robocopy)\.exe$/i
| CommandLine=/(Login Data|Local State|Cookies|key4\.db|logins\.json|Web Data|Chrome\\User Data|Edge\\User Data|Firefox\\Profiles)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Browser credential database filenames and profile paths.
* Triage Steps: Determine files copied/read and whether DPAPI decryption was attempted.
* Potential False Positives: Browser migration and forensic acquisition.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"sqlite3.exe","CommandLine":"sqlite3 \"C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\""}
```

---

### [[T1552]] - Unsecured Credentials — CQL Hub: Applications with plaintext passwords

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1552
> technique_name:: Unsecured Credentials
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: applications_with_plaintext_passwords.yml
> cql_hub_name:: Applications with plaintext passwords
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1552
> related_mitre_ids:: T1552
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: Table of applications identified as potentially handling plaintext passwords.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`applications_with_plaintext_passwords.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1552.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
"#event_simpleName" = ProcessRollup2 event_platform="Win" CommandLine=/REDACTED/
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| groupBy([FileName], function=[count(aid, distinct=true, as="Hosts")])
| sort(Hosts)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Falcon automatically attempts to redact plain-text passwords in process command lines to prevent sensitive data exposure. When this occurs, the password string is replaced with the marker `/REDACTED/`. Therefore, during analysis we specifically look for the `/REDACTED/` placeholder within command-line arguments as an indicator that Falcon has detected and masked a potential plain-text password.  Reference: https://www.reddit.com/r/crowdstrike/comments/u8ji4i/commandline_redacted/
* Key Indicators: Review query output fields and filters from `applications_with_plaintext_passwords.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1003]] - OS Credential Dumping — CQL Hub: Detect NTLMv1 Authentications

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1003
> technique_name:: OS Credential Dumping
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: detect_ntlmv1_authentications.yml
> cql_hub_name:: Detect NTLMv1 Authentications
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1003
> required_modules:: Identity
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: This query detects NTLM v1 authentications using Falcon ITP telemetry. 

* Telemetry Requirements: Identity
* Source: CQL Hub (`detect_ntlmv1_authentications.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event.dataset="falcon.identity"
| network.protocol="ntlm_v1"
| groupBy([SourceAccountUserName, host.hostname, TargetServerHostName])
```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: [Closing the Door on Net-NTLMv1: Releasing Rainbow Tables to Accelerate Protocol Deprecation](https://cloud.google.com/blog/topics/threat-intelligence/net-ntlmv1-deprecation-rainbow-tables?linkId=38338466&hl=en)
* Key Indicators: Review query output fields and filters from `detect_ntlmv1_authentications.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1003]] - OS Credential Dumping — CQL Hub: Detect NTLMv1 Authentications (Windows Event Logs)

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1003
> technique_name:: OS Credential Dumping
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: detect_ntlmv1_authentications__windows_event_logs_.yml
> cql_hub_name:: Detect NTLMv1 Authentications (Windows Event Logs)
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1003
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: This query detects NTLM v1 authentications using Windows Event Log telemetry. 

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`detect_ntlmv1_authentications__windows_event_logs_.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
| windows.EventData.AuthenticationPackageName=NTLM
| windows.EventData.LmPackageName!= "NTLM V2" 
| groupBy([windows.EventData.WorkstationName, user.target.name, windows.EventData.KeyLength])
| rename(field="windows.EventData.WorkstationName", as="Hostname")
| rename(field="user.target.name", as="Username")
| rename(field="windows.EventData.KeyLength", as="KeyLength")
| sort(field=KeyLength,type=number,order=desc)
| case{
  KeyLength = 128
  | SSP := "Yes";
  in(field="KeyLength", values=[0,40,56])
  | SSP := "No"
}
| table([Hostname,Username,KeyLength,SSP])
```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: [Closing the Door on Net-NTLMv1: Releasing Rainbow Tables to Accelerate Protocol Deprecation](https://cloud.google.com/blog/topics/threat-intelligence/net-ntlmv1-deprecation-rainbow-tables?linkId=38338466&hl=en)
* Key Indicators: Review query output fields and filters from `detect_ntlmv1_authentications__windows_event_logs_.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1528]] - Steal Application Access Token — CQL Hub: OAuth2 Token Burst — Token Harvesting (Microsoft Defender for Identity)

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1528
> technique_name:: Steal Application Access Token
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: oauth2_token_burst_token_harvesting_microsoft_defender_for_identity.yml
> cql_hub_name:: OAuth2 Token Burst — Token Harvesting (Microsoft Defender for Identity)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1528
> related_mitre_ids:: T1528
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: Detects a sudden surge in OAuth2 token requests or acquisitions within a short timeframe, as identified by Microsoft Defender for Identity. This behavior may indicate token harvesting activity, where an attacker attempts to obtain multiple access tokens to abuse authentication sessions and maintain unauthorized access.

* Telemetry Requirements: Identity
* Source: CQL Hub (`oauth2_token_burst_token_harvesting_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1528.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityLogonEvents"
| Vendor.properties.LogonType = "OAuth2:Token"
| groupBy([user.name], function=[
      count(as=token_requests),
      count(field=Vendor.properties.DestinationDeviceName, distinct=true, as=unique_destinations),
      collect(fields=[Vendor.properties.DestinationDeviceName,"Vendor.properties.AdditionalFields.ARG.CLOUD_SERVICE",Vendor.properties.Application,source.address]),
      min(@timestamp, as=start_time),
      max(@timestamp, as=end_time)
    ])
| token_requests >= 10
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 10
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([token_requests], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects a sudden surge in OAuth2 token requests or acquisitions within a short timeframe, as identified by Microsoft Defender for Identity. This behavior may indicate token harvesting activity, where an attacker attempts to obtain multiple access tokens to abuse authentication sessions and maintain unauthorized access.
* Key Indicators: Review query output fields and filters from `oauth2_token_burst_token_harvesting_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1110.003]] - Password Spraying — CQL Hub: Password Spray Many Users from Same IP Microsoft Defender for Identity

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1110.003
> technique_name:: Password Spraying
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: password_spray_many_users_from_same_ip_microsoft_defender_for_identity.yml
> cql_hub_name:: Password Spray Many Users from Same IP Microsoft Defender for Identity
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1110.003
> related_mitre_ids:: T1110.003
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: Detects multiple authentication failures across several user accounts originating from a single IP address, as identified by Microsoft Defender for Identity. This pattern is indicative of a password spraying attack where an attacker attempts common passwords against multiple users to gain unauthorized access.

* Telemetry Requirements: Identity
* Source: CQL Hub (`password_spray_many_users_from_same_ip_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1110.003.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityLogonEvents"
| Vendor.properties.LogonType = "Failed logon"
| groupBy([source.address], function=[count(as=total_failures),count(field=user.name, distinct=true, as=unique_users),collect(fields=user.name),collect(fields=Vendor.properties.DestinationDeviceName),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| unique_users > 10
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 30
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([unique_users], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects multiple authentication failures across several user accounts originating from a single IP address, as identified by Microsoft Defender for Identity. This pattern is indicative of a password spraying attack where an attacker attempts common passwords against multiple users to gain unauthorized access.
* Key Indicators: Review query output fields and filters from `password_spray_many_users_from_same_ip_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1003.006]] - DCSync — CQL Hub: Possible DC Replication (DCSync)

> [!metadata]+ Detection Metadata
> tactic:: Credential Access
> technique_id:: T1003.006
> technique_name:: DCSync
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: possible_dc_replication_dcsync.yml
> cql_hub_name:: Possible DC Replication (DCSync)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1003.006
> related_mitre_ids:: T1003.006
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Credential_Access, CQL_Hub

* Detection Objective: Detects suspicious attempts to replicate Active Directory data from a Domain Controller using the DCSync technique based on the Defender for identity module. This behavior may indicate an attacker attempting to extract sensitive credentials (such as password hashes) by mimicking domain replication requests

* Telemetry Requirements: Identity
* Source: CQL Hub (`possible_dc_replication_dcsync.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1003.006.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor="microsoft"
| #event.dataset="defender-identity.IdentityDirectoryEvents"
| event.action = "directory services replication"
| network.protocol = drsr
| groupBy([user.name,Vendor.properties.AdditionalFields.FROM.DEVICE, source.address], function=[count(as=replication_count),collect(fields=[Vendor.properties.DestinationDeviceName,Vendor.properties.DestinationIPAddress,Vendor.properties.AdditionalFields.DestinationComputerOperatingSystem,Vendor.properties.AdditionalFields.SourceComputerOperatingSystemType]),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([replication_count], order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `possible_dc_replication_dcsync.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
