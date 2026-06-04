# TA0112 - Defense Impairment

[[00_Master_CQL_Index|← Master CQL Index]]

> Purpose: Atomic CQL/Falcon LogScale detections mapped to MITRE ATT&CK Defense Impairment. Each technique section includes Obsidian metadata callouts with Dataview-style inline fields and a production-ready CQL block grounded in LogScale pipe/filter/aggregation syntax.

---

### [[T1685.005]] - Clear Windows Event Logs

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685.005
> technique_name:: Clear Windows Event Logs
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Defense_Impairment

* Detection Objective: Detect commands used to clear Windows event logs or remove PowerShell history. This is a high-confidence anti-forensics behavior.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Windows Event Log or History Clearing
// Focus: wevtutil/cl/PowerShell Clear-EventLog/remove history commands
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(wevtutil|powershell|pwsh|cmd)\.exe$/i
| CommandLine=/(wevtutil\s+(cl|clear-log)|Clear-EventLog|Remove-Item.+ConsoleHost_history|Clear-History|auditpol.+\/clear)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Explicit log/history clearing verbs.
* Triage Steps: Treat as high severity if not part of approved maintenance; preserve volatile data and review prior activity.
* Potential False Positives: Rare administrator maintenance or golden-image preparation.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"wevtutil.exe","CommandLine":"wevtutil cl Security"}
```

---

### [[T1685]] - Disable or Modify Tools

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: High
> tags:: CQL, MITRE/Defense_Impairment

* Detection Objective: Detect attempts to disable Microsoft Defender or security tooling through PowerShell, sc.exe, reg.exe, or policy registry edits.
* Telemetry Requirements: ProcessRollup2, RegistryValueSet

#### Production-Ready CQL Query:

```cql
// Title: Security Tool Disablement via CLI or Registry
// Focus: Defender disable flags, service stop, policy tamper settings
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell|pwsh|reg|sc|net)\.exe$/i
| CommandLine=/(Set-MpPreference.+Disable|DisableRealtimeMonitoring|TamperProtection|\\Windows Defender\\|WinDefend|Sense\s+(stop|disabled)|Add-MpPreference.+Exclusion)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Security product service manipulation, Defender policy settings, or exclusion creation.
* Triage Steps: Validate change-ticket context; collect exact setting modified and correlate with malware staging.
* Potential False Positives: EDR/AV troubleshooting and sanctioned deployment exclusions.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"powershell.exe","CommandLine":"Set-MpPreference -DisableRealtimeMonitoring $true"}
```

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Detection of DoH traffic to known DoH-providers

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Network
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: DoH_traffic.yml
> cql_hub_name:: Detection of DoH traffic to known DoH-providers
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: This query identifies network traffic to well-known DoH endpoints (e.g., Cloudflare, Google, Quad9, Mozilla). DoH encrypts DNS requests inside HTTPS, which enhances privacy but creates blind spots for defenders. Adversaries can exploit DoH to bypass DNS-based filtering, hide access to phishing domains, establish stealthy command-and-control channels, or exfiltrate data without triggering traditional DNS logs. Monitoring and alerting on DoH connections helps restore visibility into DNS activity—one of the most critical layers of network defense.
* Telemetry Requirements: Network
* Source: CQL Hub (`DoH_traffic.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName = DnsRequest
| in(field="DomainName", values=["cloudflare-dns.com", "dns.google", "dns.quad9.net","mozilla.cloudflare-dns.com"])
| groupBy(["ComputerName","ContextBaseFileName"])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: DNS over HTTPS (DoH) encrypts DNS queries by tunneling them through HTTPS, making them indistinguishable from regular web traffic. While this improves user privacy, it also introduces blind spots for security teams. Why it matters: - Phishing domains can be accessed without triggering DNS-based filtering. - Command-and-Control (C2) communication can blend into normal HTTPS traffic. - Data exfiltration becomes harder to detect as destination domains are hidden. Impact on organizations: Without proper monitoring or controls, DoH can undermine DNS visibility—one of the most   critical layers in network security—allowing threats to go unnoticed.
* Key Indicators: Review query output fields and filters from `DoH_traffic.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Firewall Rule Additions

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Firewall_Rule_Additions.yml
> cql_hub_name:: Firewall Rule Additions
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: This query correlates processes with Windows Firewall rule modifications they triggered, identifying which executables are creating or modifying firewall rules.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Firewall_Rule_Additions.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=ProcessRollup2
| join(query={#event_simpleName=FirewallSetRule}, field=TargetProcessId, key=ContextProcessId, include=[FirewallRule, FirewallRuleId])
| regex("(?<fileName>[^\\\\]+$)", field=ImageFileName)
| table([aid, UserSid, fileName, FirewallRuleId, FirewallRule, ImageFileName, CommandLine], limit=20000)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `Firewall_Rule_Additions.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: GenAI Usage

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: GenAI_Usage.yml
> cql_hub_name:: GenAI Usage
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: This query identifies DNS requests to GenAI services.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`GenAI_Usage.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; AWS telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=DnsRequest
| in(field=DomainName, values=[".ai", ".ai21.com", ".aleph-alpha.com", ".anthropic.com", ".assemblyai.com", ".bolt.ai", ".bubble.io", ".character.ai", ".claude.ai", ".clickup.com", ".codeium.com", ".cohere.ai", ".copy.ai", ".cursor.so", ".deepmind.com", ".deepseek.ai", ".deepl.com", ".dalle.ai", ".elevenlabs.io", ".feedhive.io", ".forefront.ai", ".grok.x.ai", ".gpt3.com", ".huggingface.co", ".inflection.ai", ".jasper.ai", ".llama.ai", ".looka.com", ".lovable.ai", ".midjourney.com", ".mistral.ai", ".openai.com", ".opus.ai", ".perplexity.ai", ".pi.ai", ".poe.com", ".replicate.com", ".runwayml.com", ".rytr.me", ".scale.com", ".stability.ai", ".sudowrite.com", ".synthesia.io", ".tabnine.com", ".together.ai", ".v0.dev", ".vercel.ai", ".vista.social", ".wordtune.com", ".writesonic.com", ".x.ai", ".you.com", "ai21.com", "aleph-alpha.com", "anthropic.com", "api.anthropic.com", "api.openai.com", "assemblyai.com", "bard.google.com", "bedrock.aws.amazon.com", "bolt.ai", "bubble.io", "character.ai", "chat.openai.com", "chatgpt.com", "claude.ai", "clickup.com", "codeium.com", "cohere.ai", "console.anthropic.com", "copilot.github.com", "copilot.microsoft.com", "copy.ai", "cursor.so", "dalle.ai", "deepmind.com", "deepseek.ai", "deepl.com", "elevenlabs.io", "ernie.baidu.com", "feedhive.io", "forefront.ai", "gemini.google.com", "gigachat.sberbank.ru", "grok.x.ai", "gpt3.com", "huggingface.co", "inflection.ai", "jasper.ai", "labs.perplexity.ai", "llama.ai", "looka.com", "lovable.ai", "midjourney.com", "mistral.ai", "openai.com", "opus.ai", "perplexity.ai", "pi.ai", "platform.openai.com", "poe.com", "replicate.com", "runwayml.com", "rytr.me", "scale.com", "stability.ai", "sudowrite.com", "synthesia.io", "tabnine.com", "together.ai", "v0.dev", "vercel.ai", "vista.social", "wordtune.com", "writesonic.com", "x.ai", "you.com"])
| groupBy([DomainName, ComputerName, event_platform])
| sort(field=_count,type=number,order=desc)

```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `GenAI_Usage.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Malicious Chrome Extension FreeVPN-One Detection

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Malicious_Chrome_Extension_FreeVPN-One_Detection.yml
> cql_hub_name:: Malicious Chrome Extension FreeVPN-One Detection
> cql_hub_author:: Aamir Muhammad
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: This Logic detects the presence of the malicious Chrome extension FreeVPN[.]One by identifying its unique extension ID across installed browsers. 
The logic further correlates this presence with network communications initiated by the extension to suspicious or untrusted domains. 
By combining extension enumeration with traffic analysis, the detection ensures high fidelity with minimal false positives. 
This layered approach strengthens visibility into malicious browser add-ons masquerading as VPN tools.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Malicious_Chrome_Extension_FreeVPN-One_Detection.yml`), author: Aamir Muhammad.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
defineTable(query={#event_simpleName=InstalledBrowserExtension
|case{
    BrowserExtensionId=/jcbiifklmgnkppebelchllpdbnibihel/iF;
    BrowserExtensionName=/FreeVPN/iF
}
| case{ 
    "BrowserExtensionStatusEnabled"="0" | BrowserExtensionStatusEnabled:="Disabled";
    "BrowserExtensionStatusEnabled"="1" | BrowserExtensionStatusEnabled:="Enabled";
    *;
}
| BrowserExtensionInstalledTimestamp := BrowserExtensionInstalledTimestamp * 1000
| "Extension Installation date" := formatTime("%d-%m-%Y %H:%M:%S.%L", field=BrowserExtensionInstalledTimestamp, locale=en_UAE, timezone="Asia/Dubai")
| "Extension(s)":=format(format="Status=%s, Installation Date=%s", field=[BrowserExtensionStatusEnabled,"Extension Installation date"])
| groupBy([event_platform, aid, UserName, BrowserProfileId, BrowserName,BrowserExtensionName], function=([collect([ComputerName,"Extension(s)",BrowserExtensionPath,BrowserExtensionRequestedPermissions])]))
| drop([_count,aid])
| case{ 
    BrowserName ="0" | BrowserName := "UNKNOWN" ;
    BrowserName="1" | BrowserName:="Firefox";
    BrowserName="2" | BrowserName:="Safari";
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    BrowserName="5" | BrowserName:="EDGE CHROMIUM";
    BrowserName="6" | BrowserName:="Internet Explorer";
    BrowserName="7" | BrowserName:="Edge Legacy";
    BrowserName="8" | BrowserName:="IE_TYPED_URL";
    BrowserName="9" | BrowserName:="FIREFOX_APP";
    *;
}}, include=[*], name="Extension")
|defineTable(query={#event_simpleName=DnsRequest | in(field="DomainName", values=["aitd.one","extrahefty.com","scan.aitd.one","freevpn.one"],ignoreCase=true)}, include=[*], name="ExtensionTraffic")
|readFile(["Extension","ExtensionTraffic"])
|groupBy([ComputerName,DomainName], function=([collect([UserName, BrowserProfileId, BrowserName,BrowserExtensionName,"Extension(s)",BrowserExtensionPath,BrowserExtensionRequestedPermissions])]))

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Reference: [GitHub Aamir-Muhammad/CrowdStrike-Queries](https://github.com/Aamir-Muhammad/CrowdStrike-Queries/blob/main/Hunting-Queries/Malicious-Chrome-Extension-FreeVPN.One-Detection.md)
* Key Indicators: Review query output fields and filters from `Malicious_Chrome_Extension_FreeVPN-One_Detection.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Assigned Sensor Update Policy

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: assigned_sensor_update_policy.yml
> cql_hub_name:: Assigned Sensor Update Policy
> cql_hub_author:: ByteRay
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: This query will output a table with all hosts and their sensor update logic / assigned sensor update policy.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`assigned_sensor_update_policy.yml`), author: ByteRay.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
defineTable(
    query={
        #repo="sensor_metadata" #data_source_name="policyinfo" #data_source_group="sensor-update"
        | groupBy(id, function=selectFromMax(field="@timestamp", include=[release_id]))
        | rename(field="id", as="sensor_update_policy_id")
    }
    , include=[sensor_update_policy_id, release_id]
    , name="policy_to_release"
    , start=1h // policyinfo is currently updated once an hour
)
| defineTable(query={
    createEvents([
        "release_id=tagged|1 release.type=N-1",
        "release_id=tagged|2 release.type=N-2",
        "release_id=tagged|3 release.type=N-1",
        "release_id=tagged|4 release.type=N-2",
        "release_id=tagged|5 release.type=N-1",
        "release_id=tagged|6 release.type=N-2",
        "release_id=tagged|11 release.type=\"Auto Latest\"",
        "release_id=tagged|12 release.type=\"Auto Latest\"",
        "release_id=tagged|13 release.type=\"Auto Latest\"",
        "release_id=tagged|16 release.type=\"Auto EA\"",
        "release_id=tagged|17 release.type=\"Auto EA\"",
        "release_id=tagged|18 release.type=\"Auto EA\""
    ])
    | kvParse()
}, include=[release_id, release.type], name="release_type_lookup")
| defineTable(
    query={
        #repo="sensor_metadata" #data_source_name="aid-policy"
        | groupBy(aid, limit=max, function=selectFromMax(field="@timestamp", include=[sensor_update_policy_id]))
    }
    , include=[aid, sensor_update_policy_id]
    , name="aid_to_policy"
    , start=1d //aid-policy is currently updated once per day
)
| readFile("aid_master_main.csv")
| in(field="ProductType", values=[1,2,3])
| match(file="aid_to_policy", field=aid, include=sensor_update_policy_id)
| match(file="policy_to_release", field=sensor_update_policy_id, include=release_id, strict=false)
| match(file="release_type_lookup", field=[release_id], include=release.type, strict=false)
| groupBy([aid, ComputerName, event_platform, Version, release.type, sensor_update_policy_id, MachineDomain, OU, SiteName, SystemManufacturer, SystemProductName], function=[], limit=max)
| default(value="-", field=[ProductType, MAC, sensor_update_policy_id, MachineDomain, OU, SiteName, SystemManufacturer, SystemProductName], replaceEmpty=true)
| default(value="Auto-Update Disabled", field=[release.type])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `assigned_sensor_update_policy.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: BYOVD Driver Load with EDR/AV Process Termination (Medusa Ransomware)

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: byovd_driver_load_with_edr_av_process_termination_medusa_ransomware.yml
> cql_hub_name:: BYOVD Driver Load with EDR/AV Process Termination (Medusa Ransomware)
> cql_hub_author:: cap10
> cql_hub_mitre_ids:: T1562.001, T1068, T1014
> related_mitre_ids:: T1685, T1068, T1014
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: Detects Bring Your Own Vulnerable Driver (BYOVD) attacks by correlating vulnerable kernel driver loads with security software termination on the same host. This technique has been actively used by the Medusa ransomware group to disable EDR/AV tooling before encryption. Covers both known-bad driver names and anomalous driver loads from user writable paths.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`byovd_driver_load_with_edr_av_process_termination_medusa_ransomware.yml`), author: cap10.
* Original CQL Hub MITRE IDs: T1562.001, T1068, T1014.
* Related/Resolved MITRE IDs: T1685, T1068, T1014.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
/* Phase 1 — Detect BYOVD: known-vulnerable or out-of-place signed drivers */
#event_simpleName = DriverLoad OR #event_simpleName = ClassifiedModuleLoad
| case {
    in(field=FileName, values=[
      "gdrv.sys", "msio64.sys", "ntiolib.sys", "kprocesshacker.sys",
      "physmem.sys", "dbk64.sys", "procexp152.sys", "NSSM.sys",
      "wantd.sys", "AsrDrv104.sys", "mhyprot2.sys"
    ]) | BYOVDIndicator := "Known vulnerable driver loaded";
    FilePath = /AppData|Temp|ProgramData|Users\\.*\\Desktop/i
      FileName = /\.sys$/i
      | BYOVDIndicator := "Driver loaded from suspicious user-writable path";
    * | BYOVDIndicator := "none";
  }
| BYOVDIndicator != "none"
| join(
    {
      #event_simpleName = TerminateProcess
      | ImageFileName = /(MsMpEng|CsAgent|CsFalconService|csshell|SentinelAgent|cbdefense|MBAMService|avp\.exe|fmon|avgnt|bdservicehost|mcshield|ekrn)\.exe$/i
      | rename(field=ImageFileName, as=TerminatedSecurity)
    },
    field=aid, key=aid
  )
| TerminatedSecurity = *

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This technique has been actively observed in Medusa ransomware campaigns, where the group drops a signed but vulnerable kernel driver (commonly repurposed anti-cheat or AV drivers) to gain kernel-level access and forcibly terminate endpoint protection before deploying the ransomware payload. CISA issued advisory AA25-071A covering Medusa's BYOVD usage.  The query is not Medusa-specific — it will detect any BYOVD campaign following the same pattern, including BlackByte, Scattered Spider, Cuba, and AvosLocker, all of which have used similar techniques.
* Key Indicators: Review query output fields and filters from `byovd_driver_load_with_edr_av_process_termination_medusa_ransomware.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Calculate Next-Gen SIEM Ingestion Total

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Network, Cloud, Other
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: calculate_next_gen_siem_ingestion_total.yml
> cql_hub_name:: Calculate Next-Gen SIEM Ingestion Total
> cql_hub_author:: AAuraa
> related_mitre_ids:: T1685
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: Calculates total NG-SIEM ingest by each Vendor (connector)
* Telemetry Requirements: Network, Cloud, Other
* Source: CQL Hub (`calculate_next_gen_siem_ingestion_total.yml`), author: AAuraa.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on AWS telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Exclude EDR logs, since these are in-platform and don't count against NG-SIEM ingest
#Vendor != "crowdstrike"

// Add up our fields that are counted for ingest (not 100% accurate, but very close to it)
| total_event := concat([@timestamp, @rawstring, #event.dataset, #event.module])
| length(field=total_event, as=event_size)

// Get our results by Vendor and translate to MB and GB
| groupBy([#Vendor], function=[sum(event_size, as=SizeBytes)], limit=max)
| SizeMB:=unit:convert("SizeBytes", binary=true, from=B, to=M, keepUnit=true)
| SizeGB:=unit:convert("SizeBytes", binary=true, from=B, to=G, keepUnit=true)

// Sort
| sort(SizeBytes, limit=200)

// Total for all vendors (uncomment for this)
//| sum(SizeBytes, as=SizeBytes)
//| SizeMB:=unit:convert("SizeBytes", binary=true, from=B, to=M, keepUnit=true)
//| SizeGB:=unit:convert("SizeBytes", binary=true, from=B, to=G, keepUnit=true)

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Calculates total NG-SIEM ingest by each Vendor (connector)  Can be altered to trim to a single vendor and assist in locating areas of large ingestion usage, such as singular firewall policies. See [this](https://www.reddit.com/r/crowdstrike/comments/1nhuu6g/mediocre_query_monday_calculating_ngsiem/) post for more information about doing this. No modules are required, but the NG-SIEM module is what facilitates the need for this query.  EDR/Endpoint/CrowdStrike native log sources are not included in this, as those are not counted against NG-SIEM ingest from a pricing perspective.
* Key Indicators: Review query output fields and filters from `calculate_next_gen_siem_ingestion_total.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Detect locally disabled RTR

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: detect_locally_disabled_rtr.yml
> cql_hub_name:: Detect locally disabled RTR
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: This query identifies hosts with locally disabled RTR.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`detect_locally_disabled_rtr.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=SensorHeartbeat
| groupBy([aid], function=selectLast([@timestamp, ComputerName, SensorStateBitMap]), limit=max)
| bitfield:extractFlags(
field=SensorStateBitMap,
 output=[
   [2, RTR_Locally_Disabled]
])
| RTR_Locally_Disabled="true"
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `detect_locally_disabled_rtr.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Detect RTR High Risk Commands

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: detect_rtr_high_risk_commands.yml
> cql_hub_name:: Detect RTR High Risk Commands
> cql_hub_author:: ByteRay GmbH
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: Detects the execution of high risk commands such as
- get
- put 
- memdump
- xmemdump
- run
- put-and-run

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`detect_rtr_high_risk_commands.yml`), author: ByteRay GmbH.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get UI Audit Events
#repo="detections" ExternalApiType=/Remote/

// Check commands for "get", "put", "memdump", "xmemdump", "run", "put-and-run"
| array:regex("Commands[]", regex="get|put|memdump|xmemdump|run|put-and-run")

// Create unified "Commands" field
| concatArray("Commands", separator="; ", as=Commands)

// Check to make sure Commands is populated
| Commands=*

// Aggregate results
| groupBy([UserName, AgentIdString], function=([collect([Commands])]))
| groupBy([UserName], function=([count(AgentIdString, as=SystemsAccssed), collect([Commands])]))
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `detect_rtr_high_risk_commands.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Domain Controllers with high load

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: domain_controllers_with_high_load.yml
> cql_hub_name:: Domain Controllers with high load
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: Domain controllers with either average CPU usage, average RAM usage that exceeds 80% or Available Disk space < 10GB.
This indicates low capacity or unexpected excessive usage.

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`domain_controllers_with_high_load.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
//Table to list DC hardware capacity
| defineTable(query={#repo=base_sensor #event_simpleName="SystemCapacity"
| in(field=cid, values=[?SelectedCid])
| match(file="aid_master_main.csv", field=[cid, aid])
| ProductType=2
// Filters
| in(field=MachineDomain, values=[?SelectedDomain])
| groupBy([cid, aid], function=selectLast([CpuProcessorName, PhysicalCoreCount, LogicalCoreCount, MemoryTotal]), limit=5000)
| MemoryTotal := unit:convert(field=MemoryTotal, to=Gi)
}, include=[cid, aid, MemoryTotal, LogicalCoreCount], name="system_capacity", start=3d)

| #repo=base_sensor #event_simpleName=ResourceUtilization
| in(field=cid, values=[?SelectedCid])
// Filter only on DC
| match(file="aid_master_main.csv", field=[cid, aid]) | ProductType=2

// Filters
| in(field=MachineDomain, values=[?SelectedDomain])

| groupBy([cid, aid], function=[ avg(AverageUsedRam, as=AverageUsedRam), avg(AverageCpuUsage, as=AverageCpuUsage), selectLast([UsedDiskSpace, AvailableDiskSpace])], limit=5000)

// Get DC capacity
| match(file="system_capacity", field=[cid, aid], strict=false)

// Memory capacity & usage
| AverageUsedRam := unit:convert(field=AverageUsedRam, from=Mi, to=Gi)
| AverageUsedRam := (AverageUsedRam/MemoryTotal)*100

| ThresholdMemory:=80
| ThresholdCPU:=80
| ThresholdDiskSpace:=10
| HighUsage:= false
| case {
  test(AverageUsedRam>=ThresholdMemory) | HighUsage:= true;
  test(AverageCpuUsage>=ThresholdCPU) | HighUsage:= true;
  test(AvailableDiskSpace<ThresholdDiskSpace) | HighUsage:= true;
}
| stats({HighUsage="true"| count(field=aid, distinct=true)})
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `domain_controllers_with_high_load.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Hunting EDR Freeze

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: hunting_edr_freeze.yml
> cql_hub_name:: Hunting EDR Freeze
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: Based on the default command line switching behavior found in the EDR-Freeze open source project:
https://github.com/TwoSevenOneT/EDR-Freeze?tab=readme-ov-file

* Telemetry Requirements: Endpoint
* Source: CQL Hub (`hunting_edr_freeze.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Look for process handles opening Falcon
#event_simpleName=FalconProcessHandleOpDetectInfo FileName="WerFaultSecure.exe"

// Check for command line switching signal
| GrandparentCommandLine=/\.exe"?\s+\d+\s+\d+$/ OR ParentCommandLine=/\.exe"?\s+\d+\s+\d+$/ OR CommandLine=/\.exe"?\s+\d+\s+\d+$/

// Create process lineage tree for easier reading
| ProcessLineage:=format(format="%s (%s)\n   └ %s (%s)\n      └ %s (%s)", field=[GrandparentImageFileName, GrandparentCommandLine, ParentImageFileName, ParentCommandLine, ImageFileName, CommandLine])

// Output deatils to table
| table([@timestamp, aid, ComputerName, ContextProcessId, ProcessLineage])

// Create direct link to Process Explorer - Uncomment the rootURL value that matches your cloud
| rootURL  := "https://falcon.crowdstrike.com/" /* US-1 */
//| rootURL  := "https://falcon.us-2.crowdstrike.com/" /* US-2 */
//| rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" /* Gov */
//| rootURL  := "https://falcon.eu-1.crowdstrike.com/"  /* EU */
| format("[Responsible Process](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "ContextProcessId"], as="Process Explorer") 

// Remove unnecessary fields
| drop([rootURL, ContextProcessId])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `hunting_edr_freeze.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Packages in Container Images - Match Parameter

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Cloud
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: packages_in_container_images___match_parameter.yml
> cql_hub_name:: Packages in Container Images - Match Parameter
> cql_hub_author:: ByteRay
> related_mitre_ids:: T1685
> required_modules:: CSPM / ASPM / DSPM
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: Searches packages using the provided parameter and returns the corresponding image repository.

* Telemetry Requirements: Cloud
* Source: CQL Hub (`packages_in_container_images___match_parameter.yml`), author: ByteRay.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): CSPM / ASPM / DSPM; container image/runtime telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
ImageScanEventType = ImageVulnerabilityEvent
| array:eval("CVEMapping[]", asArray="PackageName[]", function={PackageName := splitString(by="\|",field="CVEMapping",index=1)})
| array:drop("CVEMapping[]")
| array:contains(array="PackageName[]", value=?Package)
| groupBy([ImageInfo.Registry,ImageInfo.Repository])
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `packages_in_container_images___match_parameter.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1685]] - Disable or Modify Tools — CQL Hub: Recent RTR Sessions

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1685
> technique_name:: Disable or Modify Tools
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: recent_rtr_sessions.yml
> cql_hub_name:: Recent RTR Sessions
> cql_hub_author:: CrowdStrike
> related_mitre_ids:: T1685
> required_modules:: Insight
> cql_hub_tags:: Monitoring
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: List of the recent Real Time Response sessions that were started.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`recent_rtr_sessions.yml`), author: CrowdStrike.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight; CQL Hub lookup file availability. Validate that this telemetry/module exists in the environment before operational use.

```cql
// Get RTR Start events
#repo=detections #event_simpleName=Event_RemoteResponseSessionStartEvent

// Rename Agent ID value
| rename(field="AgentIdString", as="aid")

// Display results in table
| table([StartTimestamp, UserName, aid], limit=20000)

// Bring in data from AID Master lookup file
| aid=~match(file="aid_master_main.csv", column=[aid], strict=false)

// Convert timestamp to human-readable value
| formatTime(format="%F %T %Z", as=StartTimestamp, field=StartTimestamp)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Review query output fields and filters from `recent_rtr_sessions.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1112]] - Modify Registry

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1112
> technique_name:: Modify Registry
> logscale_stream:: RegistryValueSet
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Defense_Impairment

* Detection Objective: Detect registry modifications that reduce security, alter policy, or hide execution artifacts.
* Telemetry Requirements: RegistryValueSet, ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Suspicious Security-Relevant Registry Modification
// Focus: Policy, Defender, UAC, Winlogon, and IFEO registry edits
#event_simpleName=RegistryValueSet
| RegObjectName=/(\\Policies\\Microsoft\\Windows Defender|\\CurrentVersion\\Policies\\System|\\Winlogon|\\Image File Execution Options|\\Terminal Server|\\Services\\)/i
| RegValueName=/(DisableAntiSpyware|DisableRealtimeMonitoring|EnableLUA|Shell|Userinit|Debugger|fDenyTSConnections|Start)/i
| select([@timestamp, ComputerName, aid, UserName, ImageFileName, RegObjectName, RegValueName, RegStringValue])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: Sensitive registry paths and values modified.
* Triage Steps: Pivot to modifying process and confirm if change was authorized.
* Potential False Positives: GPO application, legitimate system configuration.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"RegistryValueSet","RegValueName":"EnableLUA","RegStringValue":"0"}
```

---

### [[T1112]] - Modify Registry — CQL Hub: Suspicious Registry Modifications

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1112
> technique_name:: Modify Registry
> logscale_stream:: Endpoint
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: Suspicious_Registry_Modifications.yml
> cql_hub_name:: Suspicious Registry Modifications
> cql_hub_author:: ByteRay GmbH
> cql_hub_mitre_ids:: T1112, T1547.001
> related_mitre_ids:: T1112, T1547.001
> required_modules:: Insight, Identity
> cql_hub_tags:: Hunting
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: This query detects suspicious registry modifications that could indicate persistence mechanisms or system configuration tampering by attackers.
* Telemetry Requirements: Endpoint
* Source: CQL Hub (`Suspicious_Registry_Modifications.yml`), author: ByteRay GmbH.
* Original CQL Hub MITRE IDs: T1112, T1547.001.
* Related/Resolved MITRE IDs: T1112, T1547.001.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Insight, Identity. Validate that this telemetry/module exists in the environment before operational use.

```cql
#event_simpleName=RegGenericValue 
| RegObjectName=/\\(Run|RunOnce|Winlogon|AppInit_DLLs|Image File Execution Options)/i
| RegValueName!=/^(ctfmon|SecurityHealth|OneDrive)$/i
| join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])
| table([aid, UserName, RegObjectName, RegValueName, RegStringValue, ProcessImageFileName])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: This query uses CrowdStrike Query Language (CQL) to detect suspicious registry modifications:  1. **Event Filtering**: `#event_simpleName=RegGenericValue`    - Searches for registry value modification events  2. **High-Risk Keys**: `RegObjectName=/\\(Run|RunOnce|Winlogon|AppInit_DLLs|Image File Execution Options)/i`    - Focuses on common persistence and execution registry locations  3. **Exclude Legitimate**: `RegValueName!=/^(ctfmon|SecurityHealth|OneDrive)$/i`    - Filters out known legitimate applications  4. **User Context**: `join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])`    - Enriches results with username information  5. **Output**: `table([aid, UserName, RegObjectName, RegValueName, RegStringValue, ProcessImageFileName])`    - Displays registry path, value, and modifying process
* Key Indicators: Review query output fields and filters from `Suspicious_Registry_Modifications.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1222.001]] - Windows Permissions

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1222.001
> technique_name:: Windows Permissions
> logscale_stream:: ProcessRollup2
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Medium
> tags:: CQL, MITRE/Defense_Impairment

* Detection Objective: Detect permission changes that grant broad access or weaken controls on sensitive paths.
* Telemetry Requirements: ProcessRollup2

#### Production-Ready CQL Query:

```cql
// Title: Suspicious Permission Weakening
// Focus: icacls/takeown/attrib granting Everyone or hiding files
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(icacls|takeown|attrib|powershell|pwsh)\.exe$/i
| CommandLine=/(icacls.+(Everyone|Users|Authenticated Users).+(F|FullControl|grant)|takeown\s+\/f|attrib\s+\+h|Set-Acl|AddAccessRule)/i
| select([@timestamp, ComputerName, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

#### Analytical Breakdown & Field Mappings:
* Key Indicators: ACL modification utilities and broad grants/hiding flags.
* Triage Steps: Validate target path and change request; check for payload staging or defense evasion.
* Potential False Positives: Software installs and admin repair operations.
#### Lab Validation (Expected True Positive Signature):
* Expected Log Profile:
```json
{"#event_simpleName":"ProcessRollup2","FileName":"icacls.exe","CommandLine":"icacls C:\\ProgramData\\svc.exe /grant Everyone:F"}
```

---

### [[T1556]] - Modify Authentication Process — CQL Hub: Account Password Not Required Changed (UAC Bypass) – Microsoft Defender for Identity

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1556
> technique_name:: Modify Authentication Process
> logscale_stream:: Identity
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: account_password_not_required_changed_uac_bypass_microsoft_defender_for_identity.yml
> cql_hub_name:: Account Password Not Required Changed (UAC Bypass) – Microsoft Defender for Identity
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1556
> related_mitre_ids:: T1556
> required_modules:: Identity
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: Detects when the “Password Not Required” flag is set or modified on a user account in Active Directory. This change weakens authentication controls and may allow account access without enforcing a password, potentially indicating misuse or attempts to bypass security policies and should be investigated.

* Telemetry Requirements: Identity
* Source: CQL Hub (`account_password_not_required_changed_uac_bypass_microsoft_defender_for_identity.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1556.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on CrowdStrike module(s): Identity; Microsoft Defender for Identity telemetry; Microsoft Defender telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor="microsoft"
| #event.dataset="defender-identity.IdentityDirectoryEvents"
| event.action = "account password not required changed"
| #event.outcome = success
| table([@timestamp,user.name,Vendor.properties.TargetAccountUpn,"Vendor.properties.AdditionalFields.TARGET_OBJECT.USER",user.target.name])

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects when the “Password Not Required” flag is set or modified on a user account in Active Directory. This change weakens authentication controls and may allow account access without enforcing a password, potentially indicating misuse or attempts to bypass security policies and should be investigated.
* Key Indicators: Review query output fields and filters from `account_password_not_required_changed_uac_bypass_microsoft_defender_for_identity.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.

---

### [[T1556]] - Modify Authentication Process — CQL Hub: Disable Strong Authentication (Microsoft Entra ID)

> [!metadata]+ Detection Metadata
> tactic:: Defense Impairment
> technique_id:: T1556
> technique_name:: Modify Authentication Process
> logscale_stream:: Other
> schema_version:: 2026.1
> last_verified:: 2026-06-01
> confidence_level:: Community
> source:: CQL Hub
> cql_hub_file:: disable_strong_authentication_microsoft_entra_id.yml
> cql_hub_name:: Disable Strong Authentication (Microsoft Entra ID)
> cql_hub_author:: Kundan Kumar
> cql_hub_mitre_ids:: T1556
> related_mitre_ids:: T1556
> cql_hub_tags:: Detection
> tags:: CQL, MITRE/Defense_Impairment, CQL_Hub

* Detection Objective: Detects when strong authentication methods (such as MFA) are disabled or weakened for a user account in Microsoft Entra ID. This action reduces account security and may indicate a legitimate administrative change or a potential attempt to bypass authentication controls and should be reviewed.

* Telemetry Requirements: Other
* Source: CQL Hub (`disable_strong_authentication_microsoft_entra_id.yml`), author: Kundan Kumar.
* Original CQL Hub MITRE IDs: T1556.

#### Production-Ready CQL Query:

> Technology dependency: This query relies on Microsoft Entra ID telemetry; Microsoft Azure telemetry. Validate that this telemetry/module exists in the environment before operational use.

```cql
#Vendor="microsoft"
| #event.module = azure
| #event.dataset = azure.entraid.audit
| Vendor.activityDisplayName ="Disable Strong Authentication"

```

#### Analytical Breakdown & Field Mappings:
* CQL Hub Explanation: Detects when strong authentication methods (such as MFA) are disabled or weakened for a user account in Microsoft Entra ID. This action reduces account security and may indicate a legitimate administrative change or a potential attempt to bypass authentication controls and should be reviewed.
* Key Indicators: Review query output fields and filters from `disable_strong_authentication_microsoft_entra_id.yml`; tune thresholds and allowlists for the local environment.
* Triage Steps: Validate source telemetry coverage, inspect returned process/user/network context, and pivot to adjacent events by host, user, process tree, or remote endpoint as applicable.
* Potential False Positives: Environment-specific administrative activity, authorized tooling, or expected platform behavior may match this community query.
