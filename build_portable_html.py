#!/usr/bin/env python3
"""Build a single portable HTML reference from the Obsidian markdown vault.

This script is intentionally dependency-free. It uses a small Markdown/Obsidian
renderer tailored to this vault's structure instead of a general Markdown
library, which keeps the export portable and repeatable on a clean system.

Example usage:

    # From the repository/vault root:
    python3 build_portable_html.py

    # Preview the generated file locally:
    python3 -m http.server 8765 --bind 127.0.0.1
    # Then open:
    # http://127.0.0.1:8765/MITRE_CQL_Mapping_Portable.html

    # Re-run after editing any .md tactic file:
    python3 build_portable_html.py

Output:
    MITRE_CQL_Mapping_Portable.html

The generated HTML is self-contained: CSS and JavaScript are embedded, and the
CQL code blocks include copy-to-clipboard buttons.
"""

from __future__ import annotations

import html
import json
import re
import urllib.request
from pathlib import Path


# The script lives in the vault root, so resolve all input/output paths relative
# to this file rather than the caller's current working directory.
ROOT = Path(__file__).resolve().parent

# Single-file HTML export target. This file can be opened directly from disk or
# served over localhost for browser QA.
OUTPUT = ROOT / "MITRE_CQL_Mapping_Portable.html"

# Official MITRE ATT&CK Enterprise STIX 2.1 bundle. The build script caches the
# JSON locally after the first successful download so the portable export can be
# rebuilt without network access.
MITRE_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
MITRE_ENTERPRISE_ATTACK_CACHE = ROOT / "enterprise-attack.json"

# Rendering order for the master index and tactic notes. Keeping this explicit
# makes the left navigation and document flow stable even if the filesystem
# returns files in a different order.
TACTIC_ORDER = [
    "00_Master_CQL_Index.md",
    "TA0043_Reconnaissance.md",
    "TA0042_Resource_Development.md",
    "TA0001_Initial_Access.md",
    "TA0002_Execution.md",
    "TA0003_Persistence.md",
    "TA0004_Privilege_Escalation.md",
    "TA0005_Stealth.md",
    "TA0112_Defense_Impairment.md",
    "TA0006_Credential_Access.md",
    "TA0007_Discovery.md",
    "TA0008_Lateral_Movement.md",
    "TA0009_Collection.md",
    "TA0011_Command_and_Control.md",
    "TA0010_Exfiltration.md",
    "TA0040_Impact.md",
]


def slugify(value: str) -> str:
    """Convert human-readable headings into stable, URL-safe fragment IDs."""
    value = value.strip().lower()
    value = re.sub(r"[^\w\s.-]+", "", value)
    value = re.sub(r"[\s_]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-") or "section"


def title_for(path: Path) -> str:
    """Return the first Markdown H1 for a note, falling back to the file stem."""
    text = path.read_text(errors="replace")
    match = re.search(r"^#\s+(.+)$", text, re.M)
    return match.group(1).strip() if match else path.stem


def collect_heading_ids(paths: list[Path]) -> dict[tuple[str, str], str]:
    """Precompute unique HTML IDs for every heading in every rendered note.

    Obsidian links can point to headings, e.g.
    [[TA0002_Execution#T1059.001 - PowerShell|PowerShell]]. To make those links
    work in the single-page HTML export, every heading gets a deterministic ID
    keyed by (note_stem, visible_heading_text).
    """
    ids: dict[tuple[str, str], str] = {}
    seen: set[str] = set()
    for path in paths:
        text = path.read_text(errors="replace")
        for match in re.finditer(r"^(#{1,6})\s+(.+)$", text, re.M):
            raw = strip_inline_markup(match.group(2).strip())
            base = f"{path.stem}-{raw}"
            hid = slugify(base)
            original = hid
            idx = 2
            while hid in seen:
                hid = f"{original}-{idx}"
                idx += 1
            seen.add(hid)
            ids[(path.stem, raw)] = hid
    return ids


def strip_inline_markup(value: str) -> str:
    """Remove link/code markup so heading IDs are based on visible text only."""
    value = re.sub(r"\[\[([^|\]]+)\|([^\]]+)\]\]", r"\2", value)
    value = re.sub(r"\[\[([^\]]+)\]\]", r"\1", value)
    value = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", value)
    value = value.replace("`", "")
    return value


def link_for_wiki(target: str, label: str, heading_ids: dict[tuple[str, str], str]) -> str:
    """Convert an Obsidian wiki link target into an in-page HTML anchor.

    Supports both note links and note-heading links:
      - [[TA0002_Execution]]
      - [[TA0002_Execution#T1059.001 - PowerShell|PowerShell]]
    """
    target = target.strip()
    label = label.strip()
    if "#" in target:
        note, heading = target.split("#", 1)
        note = note.replace(".md", "")
        hid = heading_ids.get((note, heading), slugify(f"{note}-{heading}"))
        href = f"#{hid}"
    else:
        note = target.replace(".md", "")
        href = f"#{slugify(note + '-' + title_for(ROOT / (note + '.md')) if (ROOT / (note + '.md')).exists() else note)}"
    return f'<a href="{html.escape(href)}">{html.escape(label)}</a>'


def render_inline(text: str, heading_ids: dict[tuple[str, str], str]) -> str:
    """Render a small subset of inline Markdown/Obsidian syntax.

    The renderer supports the inline constructs used by this vault:
    backtick code, bold/emphasis, Markdown links, and Obsidian wiki links.
    Placeholders are used so HTML escaping does not corrupt generated anchors
    or inline-code tags.
    """
    placeholders: list[str] = []

    def stash(value: str) -> str:
        placeholders.append(value)
        return f"\u0000{len(placeholders) - 1}\u0000"

    def repl_code(match: re.Match[str]) -> str:
        return stash(f"<code>{html.escape(match.group(1))}</code>")

    text = re.sub(r"`([^`]+)`", repl_code, text)
    text = html.escape(text)

    def repl_wiki(match: re.Match[str]) -> str:
        body = html.unescape(match.group(1))
        if "|" in body:
            target = label = ""
            for pipe in [idx for idx, char in enumerate(body) if char == "|"]:
                candidate_target = body[:pipe]
                if "#" not in candidate_target:
                    continue
                note, heading = candidate_target.split("#", 1)
                note = note.replace(".md", "").strip()
                if (note, heading.strip()) in heading_ids:
                    target = candidate_target
                    label = body[pipe + 1 :]
                    break
            if not target:
                target, label = body.split("|", 1)
        else:
            target = label = body
        return stash(link_for_wiki(target, label, heading_ids))

    text = re.sub(r"\[\[([^\]]+)\]\]", repl_wiki, text)

    def repl_md_link(match: re.Match[str]) -> str:
        label = html.unescape(match.group(1))
        dest = html.unescape(match.group(2))
        if dest.endswith(".md"):
            target_path = ROOT / dest
            target_title = title_for(target_path) if target_path.exists() else dest.removesuffix(".md")
            href = f"#{slugify(dest.removesuffix('.md') + '-' + target_title)}"
        else:
            href = dest
        return stash(f'<a href="{html.escape(href)}">{html.escape(label)}</a>')

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", repl_md_link, text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", text)
    for i, value in enumerate(placeholders):
        text = text.replace(f"\u0000{i}\u0000", value)
    return text


def is_table(lines: list[str], idx: int) -> bool:
    """Return True when the current line starts a GitHub-style Markdown table."""
    if idx + 1 >= len(lines):
        return False
    return lines[idx].startswith("|") and re.match(r"^\|\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?$", lines[idx + 1]) is not None


def split_table_row(line: str) -> list[str]:
    """Split a Markdown table row into cells after trimming outer pipes."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [cell.strip() for cell in line.split("|")]


def render_table(lines: list[str], idx: int, heading_ids: dict[tuple[str, str], str]) -> tuple[str, int]:
    """Render a Markdown table and return the next unread line index."""
    headers = split_table_row(lines[idx])
    idx += 2
    rows = []
    while idx < len(lines) and lines[idx].startswith("|"):
        rows.append(split_table_row(lines[idx]))
        idx += 1
    out = ['<div class="table-wrap"><table>']
    out.append("<thead><tr>" + "".join(f"<th>{render_inline(cell, heading_ids)}</th>" for cell in headers) + "</tr></thead>")
    out.append("<tbody>")
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{render_inline(cell, heading_ids)}</td>" for cell in row) + "</tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out), idx


def render_metadata_callout(lines: list[str], idx: int, heading_ids: dict[tuple[str, str], str]) -> tuple[str, int]:
    """Render Obsidian metadata callouts as compact key/value panels.

    The tactic notes store per-query metadata as Dataview-style inline fields:

        > [!metadata]+ Detection Metadata
        > technique_id:: T1059.001
        > confidence_level:: High

    This function turns that block into an HTML <aside>.
    """
    title = lines[idx].removeprefix("> [!metadata]+").strip() or "Metadata"
    idx += 1
    rows = []
    while idx < len(lines) and lines[idx].startswith("> "):
        row = lines[idx][2:]
        if "::" in row:
            key, value = row.split("::", 1)
            rows.append((key.strip(), value.strip()))
        idx += 1
    out = [f'<aside class="metadata"><div class="metadata-title">{html.escape(title)}</div>']
    for key, value in rows:
        out.append(
            '<div class="meta-row">'
            f'<span class="meta-key">{html.escape(key.replace("_", " "))}</span>'
            f'<span class="meta-value">{render_inline(value, heading_ids)}</span>'
            "</div>"
        )
    out.append("</aside>")
    return "\n".join(out), idx


def render_markdown(path: Path, heading_ids: dict[tuple[str, str], str]) -> str:
    """Render one Markdown note into HTML.

    This is a line-oriented renderer optimized for the vault's known patterns:
    headings, horizontal rules, blockquotes, unordered/check lists, metadata
    callouts, fenced code blocks, and tables. CQL fences receive a copy button;
    JSON and other code fences render as normal code cards.
    """
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    out: list[str] = []
    idx = 0
    in_list = False

    def close_list() -> None:
        """Close an open <ul> before rendering a non-list block."""
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    while idx < len(lines):
        line = lines[idx]

        if line.startswith("```"):
            # Fenced code blocks are copied verbatim. CQL blocks get the
            # data-copyable marker and a button that the embedded JavaScript
            # wires to navigator.clipboard.
            close_list()
            lang = line.removeprefix("```").strip() or "text"
            idx += 1
            code_lines = []
            while idx < len(lines) and not lines[idx].startswith("```"):
                code_lines.append(lines[idx])
                idx += 1
            if idx < len(lines):
                idx += 1
            code = "\n".join(code_lines).rstrip()
            copy = ' data-copyable="true"' if lang.lower() == "cql" else ""
            button = '<button class="copy-button" type="button">Copy CQL</button>' if lang.lower() == "cql" else ""
            out.append(
                f'<div class="code-card"{copy}>'
                f'<div class="code-toolbar"><span>{html.escape(lang.upper())}</span>{button}</div>'
                f'<pre><code class="language-{html.escape(lang)}">{html.escape(code)}</code></pre>'
                "</div>"
            )
            continue

        if line.startswith("> [!metadata]+"):
            # Obsidian metadata callouts are parsed before generic blockquotes.
            close_list()
            rendered, idx = render_metadata_callout(lines, idx, heading_ids)
            out.append(rendered)
            continue

        if is_table(lines, idx):
            # Tables are wrapped in .table-wrap so narrow screens can scroll
            # horizontally without causing page-level overflow.
            close_list()
            rendered, idx = render_table(lines, idx, heading_ids)
            out.append(rendered)
            continue

        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading:
            # Heading IDs must match collect_heading_ids(), otherwise generated
            # wiki links from the master checklist will not resolve.
            close_list()
            level = len(heading.group(1))
            raw = strip_inline_markup(heading.group(2).strip())
            hid = heading_ids.get((path.stem, raw), slugify(f"{path.stem}-{raw}"))
            out.append(f'<h{level} id="{hid}">{render_inline(heading.group(2).strip(), heading_ids)}</h{level}>')
            idx += 1
            continue

        if line.strip() == "---":
            # Horizontal rules separate procedure sections in the tactic notes.
            close_list()
            out.append('<hr class="section-rule">')
            idx += 1
            continue

        if line.startswith("> "):
            # Plain blockquotes, including technology dependency notices.
            close_list()
            quote = []
            while idx < len(lines) and lines[idx].startswith("> "):
                quote.append(lines[idx][2:])
                idx += 1
            out.append('<blockquote>' + "<br>".join(render_inline(q, heading_ids) for q in quote) + "</blockquote>")
            continue

        bullet = re.match(r"^\s*[-*]\s+(.+)$", line)
        if bullet:
            # Render normal bullets and Obsidian/GFM checklist items.
            if not in_list:
                out.append("<ul>")
                in_list = True
            body = bullet.group(1)
            task = re.match(r"^\[([ xX])\]\s+(.+)$", body)
            if task:
                checked = " checked" if task.group(1).lower() == "x" else ""
                item = f'<label class="task"><input type="checkbox"{checked}> <span>{render_inline(task.group(2), heading_ids)}</span></label>'
            else:
                item = render_inline(body, heading_ids)
            out.append(f"<li>{item}</li>")
            idx += 1
            continue

        if not line.strip():
            close_list()
            idx += 1
            continue

        close_list()
        out.append(f"<p>{render_inline(line.strip(), heading_ids)}</p>")
        idx += 1

    close_list()
    return "\n".join(out)


def extract_metrics(master_text: str) -> list[tuple[str, str]]:
    """Extract hero metric cards from the index's Coverage Metrics section only.

    Important: the master index also has prose bullets in Syntax Grounding. This
    function deliberately ignores those so long explanatory bullets do not get
    squeezed into the top metric-card row.
    """
    metrics = []
    in_metrics = False
    for line in master_text.splitlines():
        if line.strip() == "## Coverage Metrics":
            in_metrics = True
            continue
        if in_metrics and line.startswith("## "):
            break
        if not in_metrics:
            continue
        match = re.match(r"-\s+([^:]+):\s+(.+)$", line)
        if match:
            metrics.append((match.group(1).strip(), match.group(2).strip()))
        if line.startswith("| Tactic |"):
            break
    return metrics


def attack_external_id(obj: dict) -> str:
    """Return the ATT&CK external ID, such as T1059 or TA0002, for a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def covered_technique_links(paths: list[Path], heading_ids: dict[tuple[str, str], str]) -> dict[str, str]:
    """Map covered ATT&CK technique IDs in this vault to their first rendered section.

    The project stores each procedure as a heading whose visible text starts with
    a wiki-linked technique ID, e.g. `### [[T1059]] - Command and Scripting
    Interpreter`. This function reuses the same heading IDs as the renderer so
    matrix cells can jump directly to the corresponding CQL section.
    """
    links: dict[str, str] = {}
    for path in paths:
        if path.name == "00_Master_CQL_Index.md":
            continue
        text = path.read_text(errors="replace")
        for match in re.finditer(r"^#{3}\s+(.+)$", text, re.M):
            raw = strip_inline_markup(match.group(1).strip())
            ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", raw)
            if not ids:
                continue
            href = f"#{heading_ids.get((path.stem, raw), slugify(f'{path.stem}-{raw}'))}"
            for technique_id in ids:
                links.setdefault(technique_id, href)
    return links


def load_enterprise_attack_bundle() -> dict:
    """Load the current Enterprise ATT&CK STIX bundle, preferring fresh MITRE data.

    The generated HTML should reflect the actual Enterprise matrix, so the first
    choice is MITRE's official public STIX file. If the network is unavailable,
    the most recent cached copy is used instead.
    """
    try:
        with urllib.request.urlopen(MITRE_ENTERPRISE_ATTACK_URL, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        MITRE_ENTERPRISE_ATTACK_CACHE.write_text(json.dumps(data))
        return data
    except Exception:
        if MITRE_ENTERPRISE_ATTACK_CACHE.exists():
            return json.loads(MITRE_ENTERPRISE_ATTACK_CACHE.read_text(errors="replace"))
        raise


def build_attack_matrix_html(paths: list[Path], heading_ids: dict[tuple[str, str], str]) -> str:
    """Build a collapsible Enterprise ATT&CK matrix with project coverage marks."""
    bundle = load_enterprise_attack_bundle()
    objects = bundle.get("objects", [])
    coverage_links = covered_technique_links(paths, heading_ids)
    covered_ids = set(coverage_links)

    matrices = [
        obj
        for obj in objects
        if obj.get("type") == "x-mitre-matrix"
        and obj.get("name") == "Enterprise ATT&CK"
        and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    ]
    if not matrices:
        return ""
    matrix = matrices[0]

    tactics = {
        obj["id"]: obj
        for obj in objects
        if obj.get("type") == "x-mitre-tactic"
        and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    }
    techniques = {
        obj["id"]: obj
        for obj in objects
        if obj.get("type") == "attack-pattern"
        and "enterprise-attack" in obj.get("x_mitre_domains", [])
        and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    }

    parent_by_subtechnique: dict[str, str] = {}
    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "subtechnique-of"
            and not obj.get("revoked")
            and not obj.get("x_mitre_deprecated")
        ):
            parent_by_subtechnique[obj.get("source_ref", "")] = obj.get("target_ref", "")

    subtechniques_by_parent: dict[str, list[dict]] = {}
    top_level_by_tactic: dict[str, list[dict]] = {}
    for technique in techniques.values():
        if technique.get("x_mitre_is_subtechnique"):
            parent_ref = parent_by_subtechnique.get(technique["id"])
            if parent_ref:
                subtechniques_by_parent.setdefault(parent_ref, []).append(technique)
            continue
        for phase in technique.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                top_level_by_tactic.setdefault(phase.get("phase_name", ""), []).append(technique)

    def technique_sort_key(technique: dict) -> tuple[str, str]:
        return (technique.get("name", "").lower(), attack_external_id(technique))

    total_technique_cells = 0
    covered_top_level_cells = 0
    columns = []
    for tactic_ref in matrix.get("tactic_refs", []):
        tactic = tactics.get(tactic_ref)
        if not tactic:
            continue
        tactic_name = tactic.get("name", "")
        tactic_id = attack_external_id(tactic)
        tactic_shortname = tactic.get("x_mitre_shortname", "")
        techniques_for_tactic = sorted(top_level_by_tactic.get(tactic_shortname, []), key=technique_sort_key)
        total_technique_cells += len(techniques_for_tactic)

        cards = []
        for technique in techniques_for_tactic:
            technique_id = attack_external_id(technique)
            subtechniques = sorted(subtechniques_by_parent.get(technique["id"], []), key=technique_sort_key)
            covered_subtechniques = [sub for sub in subtechniques if attack_external_id(sub) in covered_ids]
            is_covered = technique_id in covered_ids or bool(covered_subtechniques)
            if is_covered:
                covered_top_level_cells += 1
            href = coverage_links.get(technique_id, f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/")
            target_attr = "" if technique_id in coverage_links else ' target="_blank" rel="noopener noreferrer"'
            covered_label = ""
            if technique_id in covered_ids:
                covered_label = '<span class="matrix-covered-label">Covered</span>'
            elif covered_subtechniques:
                covered_label = f'<span class="matrix-covered-label">{len(covered_subtechniques)} sub covered</span>'

            subtech_html = ""
            if subtechniques:
                sub_items = []
                for subtechnique in subtechniques:
                    sub_id = attack_external_id(subtechnique)
                    sub_covered = sub_id in covered_ids
                    sub_href = coverage_links.get(sub_id, f"https://attack.mitre.org/techniques/{sub_id.replace('.', '/')}/")
                    sub_target = "" if sub_id in coverage_links else ' target="_blank" rel="noopener noreferrer"'
                    sub_items.append(
                        f'<a class="matrix-subtech{" covered" if sub_covered else ""}" href="{html.escape(sub_href)}"{sub_target}>'
                        f'<span>{html.escape(subtechnique.get("name", ""))}</span><small>{html.escape(sub_id)}</small></a>'
                    )
                subtech_html = (
                    '<details class="matrix-subtech-list">'
                    f'<summary>{len(subtechniques)} sub-techniques</summary>'
                    + "".join(sub_items)
                    + "</details>"
                )

            cards.append(
                f'<article class="matrix-technique{" covered" if is_covered else ""}" data-technique-id="{html.escape(technique_id)}">'
                f'<a href="{html.escape(href)}"{target_attr}>'
                f'<span>{html.escape(technique.get("name", ""))}</span>'
                f'<small>{html.escape(technique_id)}</small>'
                f"{covered_label}</a>"
                f"{subtech_html}"
                "</article>"
            )

        columns.append(
            '<section class="matrix-column">'
            '<div class="matrix-tactic">'
            f'<strong>{html.escape(tactic_name)}</strong>'
            f'<span>{html.escape(tactic_id)} · {len(techniques_for_tactic)} techniques</span>'
            "</div>"
            '<div class="matrix-techniques">'
            + "".join(cards)
            + "</div>"
            "</section>"
        )

    return (
        '<details class="attack-matrix">'
        '<summary>'
        '<span>MITRE ATT&CK Enterprise Matrix Coverage</span>'
        f'<small>{len(covered_ids)} covered project technique IDs · {covered_top_level_cells} highlighted matrix cells · {total_technique_cells} Enterprise technique cells</small>'
        '</summary>'
        '<div class="matrix-legend">'
        '<span><i class="legend-covered"></i> Covered by this project</span>'
        '<span><i class="legend-open"></i> Present in Enterprise ATT&CK</span>'
        '<span>Covered sub-techniques also highlight their parent technique.</span>'
        '</div>'
        '<div class="matrix-scroll"><div class="matrix-grid">'
        + "".join(columns)
        + "</div></div>"
        "</details>"
    )


def main() -> None:
    """Build the complete portable HTML document."""
    # Keep only files that exist, so the script remains tolerant if a tactic note
    # is temporarily removed or renamed during editing.
    paths = [ROOT / name for name in TACTIC_ORDER if (ROOT / name).exists()]

    # Build all heading IDs before rendering so links can point forward to later
    # sections in the document.
    heading_ids = collect_heading_ids(paths)

    # Pull metrics from the master index for the hero cards.
    master_text = (ROOT / "00_Master_CQL_Index.md").read_text(errors="replace")
    metrics = extract_metrics(master_text)

    # Sidebar tactic navigation cards are derived from each tactic note's title,
    # unique technique count, and total CQL fence count.
    tactic_cards = []
    for path in paths:
        if path.name == "00_Master_CQL_Index.md":
            continue
        title = title_for(path)
        text = path.read_text(errors="replace")
        query_count = text.count("```cql")
        technique_count = len(set(re.findall(r"^> technique_id:: (T\d+(?:\.\d+)?)$", text, re.M)))
        href = f"#{heading_ids.get((path.stem, title), slugify(path.stem + '-' + title))}"
        tactic_cards.append(
            f'<a class="tactic-card" href="{href}"><span>{html.escape(title)}</span>'
            f'<small>{technique_count} techniques / {query_count} queries</small></a>'
        )

    # Render each note as a section in one long single-page document.
    sections = []
    for path in paths:
        title = title_for(path)
        content = render_markdown(path, heading_ids)
        classes = "doc-section master-section" if path.name == "00_Master_CQL_Index.md" else "doc-section"
        sections.append(f'<section class="{classes}" data-title="{html.escape(title)}">{content}</section>')

    # Embedded JSON metadata is useful for future scripts or browser-side
    # enhancements without having to re-parse the rendered HTML.
    payload = {
        "generatedFrom": str(ROOT),
        "documents": [path.name for path in paths],
    }

    # The hero shows the first six high-level metrics from Coverage Metrics.
    metric_cards = "\n".join(
        f'<div class="metric-card"><span>{html.escape(label)}</span><strong>{html.escape(value)}</strong></div>'
        for label, value in metrics[:6]
    )
    attack_matrix = build_attack_matrix_html(paths, heading_ids)

    # Use simple placeholder replacement so the HTML template can remain a
    # readable raw string without f-string brace escaping everywhere.
    html_doc = HTML_TEMPLATE.replace("__METRIC_CARDS__", metric_cards)
    html_doc = html_doc.replace("__ATTACK_MATRIX__", attack_matrix)
    html_doc = html_doc.replace("__TACTIC_CARDS__", "\n".join(tactic_cards))
    html_doc = html_doc.replace("__CONTENT__", "\n".join(sections))
    html_doc = html_doc.replace("__PAYLOAD__", html.escape(json.dumps(payload)))
    OUTPUT.write_text(html_doc)
    print(f"Wrote {OUTPUT}")


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CrowdStrike CQL MITRE ATT&CK Mapping</title>
  <style>
    :root {
      --bg: #f6f7f9;
      --surface: #ffffff;
      --surface-2: #eef2f6;
      --ink: #17202a;
      --muted: #607080;
      --line: #d9e0e8;
      --accent: #0f766e;
      --accent-2: #b42318;
      --code-bg: #111827;
      --code-ink: #e5edf7;
      --shadow: 0 18px 48px rgba(22, 34, 51, 0.12);
      --radius: 8px;
      color-scheme: light;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.58 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .layout { min-height: 100vh; }
    .topbar {
      position: sticky;
      top: 0;
      z-index: 20;
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 14px clamp(16px, 3vw, 34px);
      background: rgba(255,255,255,0.92);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(14px);
    }
    .topbar-credit {
      margin-left: auto;
      white-space: nowrap;
      color: var(--muted);
      font-size: 13px;
    }
    .topbar-credit a {
      font-weight: 700;
      color: var(--accent);
    }
    .brand { min-width: 220px; }
    .brand strong { display: block; font-size: 15px; line-height: 1.1; }
    .brand span { color: var(--muted); font-size: 12px; }
    .search {
      width: min(560px, 100%);
      border: 1px solid var(--line);
      background: var(--surface);
      border-radius: var(--radius);
      padding: 10px 12px;
      color: var(--ink);
      outline: none;
    }
    .search:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.14); }
    .shell {
      display: grid;
      grid-template-columns: minmax(220px, 300px) minmax(0, 1fr);
      gap: 24px;
      padding: 24px clamp(16px, 3vw, 34px) 48px;
    }
    .sidebar {
      position: sticky;
      top: 78px;
      align-self: start;
      max-height: calc(100vh - 96px);
      overflow: auto;
    }
    .panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }
    .sidebar .panel { padding: 10px; }
    .tactic-card {
      display: block;
      padding: 10px 11px;
      border-radius: 6px;
      color: var(--ink);
      text-decoration: none;
    }
    .tactic-card:hover { background: var(--surface-2); text-decoration: none; }
    .tactic-card span { display: block; font-weight: 700; }
    .tactic-card small { display: block; color: var(--muted); font-size: 12px; }
    .hero {
      padding: clamp(22px, 4vw, 42px);
      margin-bottom: 22px;
      background: #0e1b2a;
      color: #f8fbff;
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }
    .hero h1 { margin: 0 0 10px; font-size: clamp(28px, 4vw, 46px); line-height: 1.08; }
    .hero p { margin: 0; color: #c7d6e6; max-width: 780px; }
    .metrics {
      display: grid;
      grid-template-columns: repeat(6, minmax(120px, 1fr));
      gap: 10px;
      margin: 18px 0 0;
    }
    .metric-card {
      display: grid;
      grid-template-rows: auto 1fr;
      align-items: start;
      min-height: 112px;
      padding: 12px;
      border: 1px solid rgba(255,255,255,0.16);
      background: rgba(255,255,255,0.07);
      border-radius: 6px;
    }
    .metric-card span { display: block; color: #a9bbce; font-size: 12px; }
    .metric-card strong {
      display: block;
      align-self: end;
      font-size: 22px;
      line-height: 1;
    }
    .attack-matrix {
      margin: 0 0 22px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .attack-matrix > summary {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      padding: 14px 16px;
      cursor: pointer;
      color: #102035;
      background: #f7fafc;
      border-bottom: 1px solid var(--line);
      font-weight: 800;
    }
    .attack-matrix > summary::-webkit-details-marker { display: none; }
    .attack-matrix > summary::before {
      content: "+";
      display: inline-grid;
      place-items: center;
      width: 24px;
      height: 24px;
      flex: 0 0 auto;
      border: 1px solid var(--line);
      border-radius: 6px;
      color: var(--accent);
      background: var(--surface);
      font-weight: 900;
    }
    .attack-matrix[open] > summary::before { content: "-"; }
    .attack-matrix > summary span { flex: 1; }
    .attack-matrix > summary small {
      color: var(--muted);
      font-weight: 600;
      text-align: right;
    }
    .matrix-legend {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
      font-size: 12px;
    }
    .matrix-legend span { display: inline-flex; align-items: center; gap: 6px; }
    .matrix-legend i {
      width: 14px;
      height: 14px;
      border-radius: 3px;
      border: 1px solid var(--line);
    }
    .legend-covered { background: #d9fbe7; border-color: #34a853 !important; }
    .legend-open { background: #ffffff; }
    .matrix-scroll {
      overflow-x: auto;
      padding: 12px;
      background: #fbfcfd;
    }
    .matrix-grid {
      display: grid;
      grid-template-columns: repeat(15, minmax(150px, 1fr));
      gap: 8px;
      min-width: 2380px;
      align-items: start;
    }
    .matrix-column {
      display: grid;
      gap: 7px;
      min-width: 0;
    }
    .matrix-tactic {
      min-height: 70px;
      display: grid;
      align-content: center;
      gap: 3px;
      padding: 8px;
      text-align: center;
      color: #2f6698;
      background: #ffffff;
      border-bottom: 2px solid #59636e;
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .matrix-tactic strong {
      display: block;
      font-size: 14px;
      line-height: 1.08;
    }
    .matrix-tactic span {
      color: #263442;
      font-size: 11px;
      line-height: 1.2;
    }
    .matrix-techniques {
      display: grid;
      gap: 4px;
    }
    .matrix-technique {
      border: 1px solid #d8dce1;
      background: #ffffff;
      min-height: 52px;
      box-shadow: inset 4px 0 0 transparent;
    }
    .matrix-technique.covered {
      border-color: #34a853;
      background: #d9fbe7;
      box-shadow: inset 4px 0 0 #15803d;
    }
    .matrix-technique > a {
      display: grid;
      gap: 2px;
      padding: 7px;
      color: #2f6698;
      text-decoration: none;
      line-height: 1.12;
    }
    .matrix-technique.covered > a { color: #064e3b; }
    .matrix-technique > a:hover span { text-decoration: underline; }
    .matrix-technique small {
      color: var(--muted);
      font-size: 10px;
    }
    .matrix-covered-label {
      width: max-content;
      margin-top: 2px;
      padding: 2px 5px;
      border-radius: 4px;
      color: #064e3b;
      background: rgba(21, 128, 61, 0.14);
      font-size: 10px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .matrix-subtech-list {
      border-top: 1px solid rgba(52, 65, 83, 0.14);
    }
    .matrix-subtech-list summary {
      padding: 5px 7px;
      color: var(--muted);
      cursor: pointer;
      font-size: 11px;
      line-height: 1.2;
    }
    .matrix-subtech {
      display: grid;
      gap: 2px;
      padding: 6px 7px;
      border-top: 1px solid rgba(52, 65, 83, 0.1);
      color: #2f6698;
      background: rgba(255,255,255,0.72);
      text-decoration: none;
      line-height: 1.12;
    }
    .matrix-subtech.covered {
      color: #064e3b;
      background: #c8f7db;
      box-shadow: inset 3px 0 0 #15803d;
    }
    .matrix-subtech small {
      color: var(--muted);
      font-size: 10px;
    }
    .content { min-width: 0; }
    .doc-section {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: clamp(18px, 3vw, 34px);
      margin-bottom: 24px;
    }
    .doc-section.hidden { display: none; }
    h1, h2, h3, h4 { letter-spacing: 0; line-height: 1.22; }
    h1 { font-size: clamp(26px, 3vw, 38px); margin: 0 0 14px; }
    h2 { margin: 32px 0 14px; font-size: 24px; border-bottom: 1px solid var(--line); padding-bottom: 8px; }
    h3 { margin: 30px 0 12px; font-size: 20px; color: #102035; }
    h4 { margin: 22px 0 10px; font-size: 15px; text-transform: uppercase; color: var(--muted); }
    p, ul, blockquote, .table-wrap, .metadata, .code-card { margin-top: 0; margin-bottom: 16px; }
    ul { padding-left: 22px; }
    li { margin: 6px 0; }
    .task { display: inline-flex; gap: 8px; align-items: flex-start; }
    blockquote {
      border-left: 4px solid var(--accent);
      background: #edf7f5;
      padding: 12px 14px;
      border-radius: 0 6px 6px 0;
      color: #25424b;
    }
    .section-rule {
      border: 0;
      border-top: 1px solid var(--line);
      margin: 28px 0;
    }
    .metadata {
      display: grid;
      gap: 6px;
      padding: 12px;
      background: #f7fafc;
      border: 1px solid var(--line);
      border-radius: var(--radius);
    }
    .metadata-title { font-weight: 800; color: #223044; margin-bottom: 2px; }
    .meta-row { display: grid; grid-template-columns: minmax(120px, 190px) minmax(0, 1fr); gap: 8px; }
    .meta-key { color: var(--muted); text-transform: capitalize; }
    .meta-value { color: var(--ink); overflow-wrap: anywhere; }
    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: var(--radius);
    }
    table { width: 100%; border-collapse: collapse; min-width: 620px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { background: #f2f5f8; font-size: 13px; color: #354356; }
    tr:last-child td { border-bottom: 0; }
    code {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.92em;
      background: #eef3f8;
      border: 1px solid #dce5ee;
      border-radius: 4px;
      padding: 1px 4px;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .code-card {
      border-radius: var(--radius);
      background: var(--code-bg);
      border: 1px solid #202b3b;
      overflow: hidden;
    }
    .code-toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 8px 10px;
      background: #0b1220;
      color: #9fb0c6;
      font-size: 12px;
      border-bottom: 1px solid #202b3b;
    }
    .copy-button {
      min-height: 30px;
      padding: 6px 10px;
      border: 1px solid #3a4a63;
      border-radius: 6px;
      color: #eaf2ff;
      background: #182338;
      cursor: pointer;
      font: inherit;
    }
    .copy-button:hover { background: #22314c; }
    .copy-button.copied { border-color: #34d399; color: #d1fae5; }
    pre {
      margin: 0;
      padding: 15px;
      overflow: auto;
      max-height: 620px;
      color: var(--code-ink);
    }
    pre code {
      display: block;
      background: transparent;
      border: 0;
      padding: 0;
      color: inherit;
      font-size: 13px;
      line-height: 1.52;
      white-space: pre;
      overflow-wrap: normal;
      word-break: normal;
    }
    mark { background: #fff2a8; color: inherit; padding: 0 2px; border-radius: 3px; }
    .no-results {
      display: none;
      padding: 18px;
      border: 1px dashed var(--line);
      border-radius: var(--radius);
      color: var(--muted);
      background: var(--surface);
    }
    .no-results.visible { display: block; }
    .search-status {
      margin: -4px 0 14px;
      color: var(--muted);
      font-size: 13px;
    }
    .checklist-actions {
      display: flex;
      justify-content: flex-end;
      margin: -4px 0 14px;
    }
    .reset-checklist {
      min-height: 30px;
      padding: 6px 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      color: var(--muted);
      background: var(--surface);
      cursor: pointer;
      font: inherit;
      font-size: 13px;
    }
    .reset-checklist:hover {
      color: var(--ink);
      background: var(--surface-2);
    }
    .tactic-card.hidden { display: none; }
    @media (max-width: 1100px) {
      .metrics { grid-template-columns: repeat(3, minmax(120px, 1fr)); }
      .shell { grid-template-columns: 1fr; }
      .sidebar { position: static; max-height: none; }
      .sidebar .panel { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 4px; }
    }
    @media (max-width: 720px) {
      body { font-size: 14px; }
      .topbar { align-items: stretch; flex-direction: column; }
      .brand { min-width: 0; }
      .topbar-credit { align-self: flex-end; margin-left: 0; text-align: right; white-space: normal; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .sidebar .panel { grid-template-columns: 1fr; }
      .doc-section { padding: 16px; }
      .meta-row { grid-template-columns: 1fr; gap: 2px; }
      h2 { font-size: 21px; }
      h3 { font-size: 18px; }
      table { min-width: 520px; }
      .attack-matrix > summary {
        align-items: flex-start;
        flex-wrap: wrap;
      }
      .attack-matrix > summary small {
        flex-basis: 100%;
        text-align: left;
        padding-left: 31px;
      }
      .matrix-grid {
        grid-template-columns: repeat(15, 150px);
        min-width: 2260px;
      }
    }
    @media print {
      .topbar, .sidebar, .copy-button { display: none; }
      .shell { display: block; padding: 0; }
      .doc-section, .hero { box-shadow: none; border: 0; }
      pre { max-height: none; white-space: pre-wrap; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <header class="topbar">
      <div class="brand">
        <strong>CrowdStrike CQL Mapping</strong>
        <span>Portable MITRE ATT&CK Reference</span>
      </div>
      <input id="search" class="search" type="search" placeholder="Search tactics, techniques, procedures, fields, or CQL..." autocomplete="off">
      <div class="topbar-credit">by: <a href="https://www.linkedin.com/in/arronjablonowski/" target="_blank" rel="noopener noreferrer">Arron Jablonowski</a></div>
    </header>
    <div class="shell">
      <nav class="sidebar" aria-label="Tactic navigation">
        <div class="panel">
          __TACTIC_CARDS__
        </div>
      </nav>
      <main class="content">
        <section class="hero">
          <h1>CrowdStrike CQL MITRE ATT&CK Mapping</h1>
          <p>A curated portable reference for CrowdStrike LogScale CQL hunting content mapped to current ATT&CK tactics, techniques, and procedures.</p>
          <div class="metrics">
            __METRIC_CARDS__
          </div>
        </section>
        __ATTACK_MATRIX__
        <div id="searchStatus" class="search-status">Showing all sections.</div>
        <div class="checklist-actions">
          <button id="resetChecklist" class="reset-checklist" type="button">Reset checklist</button>
        </div>
        <div id="noResults" class="no-results">No matching sections found.</div>
        __CONTENT__
      </main>
    </div>
  </div>
  <script type="application/json" id="export-metadata">__PAYLOAD__</script>
  <script>
    const search = document.getElementById('search');
    const sections = Array.from(document.querySelectorAll('.doc-section'));
    const navCards = Array.from(document.querySelectorAll('.tactic-card'));
    const noResults = document.getElementById('noResults');
    const searchStatus = document.getElementById('searchStatus');
    const resetChecklist = document.getElementById('resetChecklist');
    const checklistKey = 'mitre-cql-coverage-checklist-v1';

    const normalizeSearchText = (value) => {
      return (value || '')
        .toLowerCase()
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/\s+/g, ' ')
        .trim();
    };

    // Cache searchable text once at page load. This avoids the hidden-section
    // problem where innerText can become empty after display:none is applied.
    sections.forEach((section) => {
      section.dataset.searchText = normalizeSearchText(section.textContent);
    });
    navCards.forEach((card) => {
      card.dataset.searchText = normalizeSearchText(card.textContent);
      const targetId = (card.getAttribute('href') || '').replace(/^#/, '');
      const target = targetId ? document.getElementById(targetId) : null;
      card._targetSection = target ? target.closest('.doc-section') : null;
    });

    const checklistInputs = Array.from(document.querySelectorAll('.master-section .task input[type="checkbox"]'));
    const loadChecklistState = () => {
      try {
        return JSON.parse(localStorage.getItem(checklistKey) || '{}');
      } catch {
        return {};
      }
    };
    const saveChecklistState = () => {
      const state = {};
      checklistInputs.forEach((input) => {
        if (input.dataset.checkId) {
          state[input.dataset.checkId] = input.checked;
        }
      });
      localStorage.setItem(checklistKey, JSON.stringify(state));
    };
    const checklistState = loadChecklistState();
    checklistInputs.forEach((input, index) => {
      const labelText = normalizeSearchText(input.closest('.task')?.innerText || `item ${index}`);
      input.dataset.checkId = `${index}:${labelText}`;
      if (Object.prototype.hasOwnProperty.call(checklistState, input.dataset.checkId)) {
        input.checked = Boolean(checklistState[input.dataset.checkId]);
      }
      input.addEventListener('change', saveChecklistState);
    });
    resetChecklist.addEventListener('click', () => {
      checklistInputs.forEach((input) => {
        input.checked = false;
      });
      localStorage.removeItem(checklistKey);
    });

    document.addEventListener('click', async (event) => {
      const button = event.target.closest('.copy-button');
      if (!button) return;
      const card = button.closest('.code-card');
      const code = card ? card.querySelector('pre code') : null;
      if (!code) return;
      try {
        await navigator.clipboard.writeText(code.innerText);
        button.textContent = 'Copied';
        button.classList.add('copied');
        setTimeout(() => {
          button.textContent = 'Copy CQL';
          button.classList.remove('copied');
        }, 1400);
      } catch (error) {
        const textarea = document.createElement('textarea');
        textarea.value = code.innerText;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        textarea.remove();
        button.textContent = 'Copied';
        button.classList.add('copied');
        setTimeout(() => {
          button.textContent = 'Copy CQL';
          button.classList.remove('copied');
        }, 1400);
      }
    });

    search.addEventListener('input', () => {
      const value = normalizeSearchText(search.value);
      const terms = value.split(' ').filter(Boolean);
      let visible = 0;
      sections.forEach((section) => {
        const haystack = section.dataset.searchText || '';
        const match = terms.length === 0 || terms.every((term) => haystack.includes(term));
        section.classList.toggle('hidden', !match);
        if (match) visible += 1;
      });
      navCards.forEach((card) => {
        const haystack = card.dataset.searchText || '';
        const cardMatch = terms.length === 0 || terms.every((term) => haystack.includes(term));
        const sectionMatch = card._targetSection && !card._targetSection.classList.contains('hidden');
        const match = cardMatch || sectionMatch;
        card.classList.toggle('hidden', !match);
      });
      noResults.classList.toggle('visible', visible === 0);
      searchStatus.textContent = terms.length === 0
        ? 'Showing all sections.'
        : `Showing ${visible} of ${sections.length} sections.`;
    });
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
