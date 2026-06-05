# CrowdStrike CQL MITRE ATT&CK Mapping

A curated Obsidian and portable HTML reference that maps CrowdStrike Falcon SIEM / LogScale CQL hunting queries to the MITRE ATT&CK Enterprise framework.

This project is designed for defenders who want a practical, searchable hunting library organized by tactic, technique, and procedure, with CQL blocks ready to copy into CrowdStrike LogScale.

## Highlights

- 15 MITRE ATT&CK Enterprise tactics covered
- 131 unique ATT&CK techniques covered
- 267 procedure sections and CQL queries
- 159 community queries integrated from CQL Hub
- Obsidian-friendly markdown with Dataview-style metadata
- Single-file portable HTML export with search, copy buttons, checklist state, and ATT&CK matrix coverage
- Technology dependency notices for queries that rely on specific products or modules, such as Microsoft Defender telemetry or Falcon modules

## Portable HTML

The primary shareable artifact is:

```text
MITRE_CQL_Mapping_Portable.html
```

Open it directly in a browser, or serve it locally:

```bash
python3 -m http.server 8765 --bind 127.0.0.1
```

Then browse to:

```text
http://127.0.0.1:8765/MITRE_CQL_Mapping_Portable.html
```

The portable HTML includes:

- Responsive layout for desktop and narrow screens
- Sidebar tactic navigation
- Full-text search across tactics, techniques, procedure notes, fields, and CQL
- Copy-to-clipboard buttons for every CQL block
- Persistent Global Coverage Checklist state using local browser storage
- Collapsible MITRE ATT&CK Enterprise matrix with covered techniques highlighted in green

![Birtha HTML report overview](https://github.com/ArronJablonowski/CQL_Mapped_to_Mitre/blob/main/__pycache__/html_mitre_mapping.png?raw=true)

Collapsible MITRE ATT&CK Enterprise matrix. 
![Birtha HTML report overview](https://github.com/ArronJablonowski/CQL_Mapped_to_Mitre/blob/main/__pycache__/mitre_coverage.png?raw=true)

## Obsidian Vault

The markdown files are formatted for Obsidian and organized by ATT&CK tactic:

```text
00_Master_CQL_Index.md
TA0043_Reconnaissance.md
TA0042_Resource_Development.md
TA0001_Initial_Access.md
TA0002_Execution.md
TA0003_Persistence.md
TA0004_Privilege_Escalation.md
TA0005_Stealth.md
TA0112_Defense_Impairment.md
TA0006_Credential_Access.md
TA0007_Discovery.md
TA0008_Lateral_Movement.md
TA0009_Collection.md
TA0011_Command_and_Control.md
TA0010_Exfiltration.md
TA0040_Impact.md
```

Each tactic file contains procedure sections with:

- ATT&CK technique metadata
- Detection objective
- Telemetry requirements
- Production-ready CQL query
- Analytical breakdown and field mappings
- Triage notes and false-positive guidance where available

## Regenerating the HTML

After editing markdown files, rebuild the portable HTML:

```bash
python3 build_portable_html.py
```

The build script:

- Renders the Obsidian markdown vault into one portable HTML file
- Adds CQL copy buttons
- Builds the sidebar and metrics from the markdown content
- Downloads and caches the official MITRE ATT&CK Enterprise STIX bundle for matrix generation
- Falls back to the cached `enterprise-attack.json` file when offline

## Coverage Metrics

| Metric | Count |
|---|---:|
| Tactics covered | 15 |
| Unique ATT&CK techniques covered | 131 |
| Procedure sections covered | 267 |
| Total CQL queries | 267 |
| Original vault queries | 108 |
| CQL Hub queries | 159 |

## Query Notes

The CQL content is intentionally conservative and Falcon-oriented. Common field names include:

```text
ImageFileName
FileName
ParentBaseFileName
CommandLine
UserName
ComputerName
TargetFileName
RegObjectName
RegValueName
RemoteAddressIP4
RemotePort
DomainName
ContextProcessId
TargetProcessId
```

Community CQL Hub queries preserve source context and are marked with metadata such as `source:: CQL Hub`, original source filenames, required modules, and technology dependency notices.

## Sources

- MITRE ATT&CK Enterprise: https://attack.mitre.org/
- MITRE ATT&CK STIX data: https://github.com/mitre-attack/attack-stix-data
- CQL Hub: https://cql-hub.com/
- CrowdStrike Falcon LogScale / Falcon SIEM CQL documentation

## Disclaimer

These detections are a hunting and reference resource. Validate syntax, field availability, telemetry coverage, and environmental false positives in your own CrowdStrike tenant before using queries for alerting or production detection logic.

## Author

Created and curated by [Arron Jablonowski](https://www.linkedin.com/in/arronjablonowski/).
