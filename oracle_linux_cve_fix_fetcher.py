#!/usr/bin/env python3
"""
oracle_linux_cve_fix_fetcher.py

Fetch updated kernel packages from Oracle Linux ELSA advisories for specified
CVE IDs, Oracle Linux version, and architecture, skipping .src.rpm files.

Dependencies:
  pip install requests beautifulsoup4

Usage examples:
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024 --version 9 --arch x86_64
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024,CVE-2023-22025 --version 9 --arch x86_64
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 9 --arch aarch64 --output-file report.txt
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 9 --arch x86_64 --format json --output-file report.json
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024 --version 9 --arch x86_64 --verbose --delay 0.5
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 8 --arch x86_64 --format html --output-file report.html
"""

import argparse
import csv
import html as html_lib
import io
import json
import logging
import re
import shutil
import sys
import textwrap
import time
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Set

CVE_BASE_URL = "https://linux.oracle.com/cve/"
USER_AGENT = "oracle-linux-cve-fix-fetcher/1.1 (+https://linuxtrek.com)"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

logger = logging.getLogger("cve_fetcher")


class Colors:
    """ANSI color helper. All codes become empty strings when color is disabled."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def cyan(self, text: str) -> str:
        return self._wrap("1;36", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def green(self, text: str) -> str:
        return self._wrap("1;32", text)

    def red(self, text: str) -> str:
        return self._wrap("1;31", text)


def build_session(max_retries: int = 3, backoff_factor: float = 0.5) -> requests.Session:
    """Create a requests Session with retry/backoff and a proper User-Agent."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    retry_kwargs = dict(
        total=max_retries,
        connect=max_retries,
        read=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        raise_on_status=False,
    )
    try:
        # urllib3 >= 1.26
        retry = Retry(allowed_methods=("GET",), **retry_kwargs)
    except TypeError:
        # urllib3 < 1.26
        retry = Retry(method_whitelist=("GET",), **retry_kwargs)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def fetch_page(session: requests.Session, url: str, timeout: int = 30) -> str:
    resp = session.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def validate_cve_id(cve_id: str) -> bool:
    return bool(CVE_ID_RE.match(cve_id.strip()))


def find_elsa_links(session: requests.Session, cve_id: str, version: str) -> List[str]:
    url = f"{CVE_BASE_URL}{cve_id}.html"
    html = fetch_page(session, url)
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for row in soup.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) >= 2:
            platform = cells[0].get_text(strip=True)
            link_tag = cells[1].find("a", href=True)
            if link_tag and f"Oracle Linux version {version}" in platform:
                href = link_tag["href"]
                full_link = href if href.startswith("http") else urljoin(url, href)
                links.append(full_link)
    return links


def is_elsa_for_version(html: str, version: str) -> bool:
    text = html.lower()
    return f"oracle linux {version}" in text or f"ol{version}" in text


def extract_packages_for_arch(elsa_html: str, version: str, arch: str) -> List[str]:
    soup = BeautifulSoup(elsa_html, "html.parser")
    target_label = f"oracle linux {version} ({arch})"
    table = None
    for t in soup.find_all("table"):
        header_text = " ".join(
            td.get_text(strip=True).lower() for td in t.find_all(["th", "td"])[:3]
        )
        if "release/architecture" in header_text and "filename" in header_text:
            table = t
            break
    if table is None:
        return []
    packages = []
    capturing = False
    for row in table.find_all("tr")[1:]:
        cells = [c.get_text(strip=True) for c in row.find_all("td")]
        if not cells:
            continue
        rel = cells[0].lower() if cells[0] else ""
        filename = cells[1] if len(cells) > 1 else None
        if rel:
            capturing = (rel == target_label)
        if capturing and filename and not filename.endswith(".src.rpm"):
            packages.append(filename)
        if capturing and rel and rel != target_label:
            break
    return packages


def get_packages_from_cve(
    session: requests.Session,
    cve_id: str,
    version: str,
    arch: str,
    delay: float = 0.0,
    max_workers: int = 8,
) -> Optional[Dict[str, List[str]]]:
    try:
        links = find_elsa_links(session, cve_id, version)
    except requests.exceptions.HTTPError as e:
        logger.debug("HTTP error fetching CVE page for %s: %s", cve_id, e)
        return None
    except requests.exceptions.RequestException as e:
        logger.warning("Network error fetching CVE page for %s: %s", cve_id, e)
        return None

    results: Dict[str, List[str]] = {}
    if not links:
        return results

    if delay:
        time.sleep(delay)

    with ThreadPoolExecutor(max_workers=min(max_workers, len(links))) as executor:
        future_to_link = {
            executor.submit(fetch_page, session, link): link for link in links
        }
        for future in as_completed(future_to_link):
            link = future_to_link[future]
            try:
                html = future.result()
            except requests.exceptions.RequestException as e:
                logger.warning("Failed to fetch ELSA page %s: %s", link, e)
                continue
            if is_elsa_for_version(html, version):
                pkgs = extract_packages_for_arch(html, version, arch)
                elsa_id = link.rstrip("/").split("/")[-1].split(".")[0]
                if pkgs:
                    results[elsa_id] = pkgs
    return results


def split_base_version(pkg: str) -> Tuple[str, str]:
    """
    Split an RPM filename into (base_name, version-release). Assumes the last
    two hyphen-separated segments (before .rpm) are version and release.
    """
    if pkg.endswith(".rpm"):
        pkg = pkg[:-4]
    parts = pkg.split("-")
    if len(parts) >= 3:
        base = "-".join(parts[:-2])
        version_release = "-".join(parts[-2:])
    else:
        base = pkg
        version_release = ""
    return base, version_release


def dedupe_preserve_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out = []
    for item in items:
        key = item.strip().upper()
        if key and key not in seen:
            seen.add(key)
            out.append(item.strip())
    return out


def render_text_report(
    base_versions: Dict[str, Dict[str, Dict[str, Set[str]]]],
    unavailable_cves: List[str],
    invalid_cves: List[str],
    elapsed: float,
    ol_version: str = "",
    arch: str = "",
    cve_count: int = 0,
    color: Optional[Colors] = None,
) -> str:
    c = color or Colors(enabled=False)
    term_width = shutil.get_terminal_size(fallback=(120, 20)).columns
    term_width = max(term_width, 80)

    output_lines: List[str] = []

    # ---- Summary header -------------------------------------------------
    unique_elsas: Set[str] = set()
    unique_cves_matched: Set[str] = set()
    row_count = 0
    for base, versions in base_versions.items():
        for version, info in versions.items():
            row_count += 1
            unique_elsas |= info["elsas"]
            unique_cves_matched |= info["cves"]

    title = f" Oracle Linux {ol_version} ({arch}) — CVE Fix Report "
    output_lines.append(c.cyan(title.center(term_width, "=")))
    summary_bits = [
        f"CVEs checked: {c.bold(str(cve_count))}",
        f"matched: {c.green(str(len(unique_cves_matched)))}",
    ]
    if unavailable_cves:
        summary_bits.append(f"unavailable: {c.red(str(len(unavailable_cves)))}")
    if invalid_cves:
        summary_bits.append(f"invalid: {c.red(str(len(invalid_cves)))}")
    summary_bits.append(f"packages: {c.bold(str(row_count))}")
    summary_bits.append(f"ELSAs: {c.bold(str(len(unique_elsas)))}")
    output_lines.append("  " + (c.dim(" | ").join(summary_bits)))
    output_lines.append("")

    # ---- Main table -------------------------------------------------------
    if base_versions:
        rows = []
        for base in sorted(base_versions.keys()):
            for version in sorted(base_versions[base].keys()):
                info = base_versions[base][version]
                rows.append((base, version, sorted(info["elsas"]), sorted(info["cves"])))

        col1_width = min(max(len("Base Package"), max(len(r[0]) for r in rows)), 40)
        col2_width = min(max(len("Version (pkg)"), max(len(r[1]) for r in rows)), 50)
        col3_width = min(max(len("ELSAs"), max(len(", ".join(r[2])) for r in rows)), 24)

        fixed_width = col1_width + col2_width + col3_width + len(" | ") * 3
        cve_col_width = max(term_width - fixed_width, 20)

        sep = c.dim("-" * term_width)
        double_sep = c.dim("=" * term_width)

        header_plain = f"{'Base Package':<{col1_width}} | {'Version (pkg)':<{col2_width}} | {'ELSAs':<{col3_width}} | CVEs"
        output_lines.append(double_sep)
        output_lines.append(c.bold(header_plain))
        output_lines.append(sep)

        current_base = None
        for base, version, elsas, cves in rows:
            if current_base is not None and base != current_base:
                output_lines.append(sep)
            current_base = base

            elsas_str = ", ".join(elsas)
            cve_str = ", ".join(cves)
            wrapped_cves = textwrap.wrap(cve_str, width=cve_col_width) or [""]

            base_disp = c.bold(base[:col1_width].ljust(col1_width)) if color and color.enabled else f"{base[:col1_width]:<{col1_width}}"
            for idx, line in enumerate(wrapped_cves):
                if idx == 0:
                    output_lines.append(
                        f"{base_disp} | {version[:col2_width]:<{col2_width}} | "
                        f"{elsas_str[:col3_width]:<{col3_width}} | {c.yellow(line)}"
                    )
                else:
                    output_lines.append(
                        f"{'':<{col1_width}} | {'':<{col2_width}} | {'':<{col3_width}} | {c.yellow(line)}"
                    )
        output_lines.append(double_sep)
    else:
        output_lines.append(c.dim("=" * term_width))
        output_lines.append("No packages found for the given CVEs/version/arch.")
        output_lines.append(c.dim("=" * term_width))

    if invalid_cves:
        output_lines.append("")
        output_lines.append(c.red("Skipped — invalid CVE ID format (expected CVE-YYYY-NNNN):"))
        output_lines.append("  " + ", ".join(sorted(invalid_cves)))

    if unavailable_cves:
        output_lines.append("")
        output_lines.append(c.red("Not available / not accessible:"))
        output_lines.append("  " + ", ".join(sorted(unavailable_cves)))

    output_lines.append("")
    output_lines.append(c.dim(f"Finished in {elapsed:.2f} seconds."))
    return "\n".join(output_lines)


def render_json_report(
    base_versions: Dict[str, Dict[str, Dict[str, Set[str]]]],
    unavailable_cves: List[str],
    invalid_cves: List[str],
    elapsed: float,
) -> str:
    packages = []
    for base in sorted(base_versions.keys()):
        for version in sorted(base_versions[base].keys()):
            info = base_versions[base][version]
            packages.append({
                "base_package": base,
                "version": version,
                "elsas": sorted(info["elsas"]),
                "cves": sorted(info["cves"]),
            })
    payload = {
        "packages": packages,
        "unavailable_cves": sorted(unavailable_cves),
        "invalid_cves": sorted(invalid_cves),
        "elapsed_seconds": round(elapsed, 2),
    }
    return json.dumps(payload, indent=2)


def render_csv_report(base_versions: Dict[str, Dict[str, Dict[str, Set[str]]]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["base_package", "version", "elsas", "cves"])
    for base in sorted(base_versions.keys()):
        for version in sorted(base_versions[base].keys()):
            info = base_versions[base][version]
            writer.writerow([
                base,
                version,
                "; ".join(sorted(info["elsas"])),
                "; ".join(sorted(info["cves"])),
            ])
    return buf.getvalue()


def render_html_report(
    base_versions: Dict[str, Dict[str, Dict[str, Set[str]]]],
    unavailable_cves: List[str],
    invalid_cves: List[str],
    elapsed: float,
    ol_version: str = "",
    arch: str = "",
    cve_count: int = 0,
) -> str:
    esc = html_lib.escape

    rows = []
    unique_elsas: Set[str] = set()
    unique_cves_matched: Set[str] = set()
    for base in sorted(base_versions.keys()):
        for version in sorted(base_versions[base].keys()):
            info = base_versions[base][version]
            elsas = sorted(info["elsas"])
            cves = sorted(info["cves"])
            unique_elsas |= info["elsas"]
            unique_cves_matched |= info["cves"]
            rows.append((base, version, elsas, cves))

    def cve_badges(cves: List[str]) -> str:
        return "".join(f'<span class="badge cve">{esc(c)}</span>' for c in cves)

    def elsa_badges(elsas: List[str]) -> str:
        return "".join(f'<span class="badge elsa">{esc(e)}</span>' for e in elsas)

    table_rows = "\n".join(
        f'''      <tr>
        <td class="pkg">{esc(base)}</td>
        <td class="ver">{esc(version)}</td>
        <td>{elsa_badges(elsas)}</td>
        <td>{cve_badges(cves)}</td>
      </tr>'''
        for base, version, elsas, cves in rows
    )

    if not rows:
        table_rows = '<tr><td colspan="4" class="empty">No packages found for the given CVEs/version/arch.</td></tr>'

    def id_list(items: List[str], css_class: str) -> str:
        if not items:
            return '<span class="empty">None</span>'
        return "".join(f'<span class="badge {css_class}">{esc(i)}</span>' for i in sorted(items))

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oracle Linux {esc(ol_version)} ({esc(arch)}) — CVE Fix Report</title>
<style>
  :root {{
    --bg: #0f1420;
    --panel: #161d2e;
    --border: #2a3348;
    --text: #e6e9f0;
    --muted: #8b94a8;
    --accent: #4fb0ff;
    --green: #35d488;
    --amber: #f2b84b;
    --red: #ff6b6b;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 2.5rem 1.5rem;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{
    font-size: 1.5rem;
    margin: 0 0 0.25rem;
    font-weight: 650;
  }}
  .subtitle {{ color: var(--muted); margin: 0 0 1.75rem; font-size: 0.9rem; }}
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 0.75rem;
    margin-bottom: 2rem;
  }}
  .stat {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.9rem 1rem;
  }}
  .stat .num {{ font-size: 1.6rem; font-weight: 700; }}
  .stat .label {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }}
  .stat.accent .num {{ color: var(--accent); }}
  .stat.green .num {{ color: var(--green); }}
  .stat.amber .num {{ color: var(--amber); }}
  .stat.red .num {{ color: var(--red); }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    font-size: 0.88rem;
  }}
  thead th {{
    text-align: left;
    padding: 0.7rem 0.9rem;
    background: #1c2438;
    color: var(--muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--border);
  }}
  tbody td {{
    padding: 0.65rem 0.9rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #1a2236; }}
  td.pkg {{ font-weight: 600; }}
  td.ver {{ color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    margin: 0.12rem 0.25rem 0.12rem 0;
    border-radius: 999px;
    font-size: 0.76rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    white-space: nowrap;
  }}
  .badge.cve {{ background: rgba(255, 107, 107, 0.12); color: var(--red); border: 1px solid rgba(255, 107, 107, 0.3); }}
  .badge.elsa {{ background: rgba(79, 176, 255, 0.12); color: var(--accent); border: 1px solid rgba(79, 176, 255, 0.3); }}
  .empty {{ color: var(--muted); font-style: italic; text-align: center; padding: 1.5rem; }}
  .footer-notes {{ margin-top: 1.75rem; }}
  .footer-notes h2 {{ font-size: 0.95rem; margin: 1.25rem 0 0.5rem; }}
  footer {{
    margin-top: 2.5rem;
    color: var(--muted);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    padding-top: 1rem;
  }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>Oracle Linux {esc(ol_version)} ({esc(arch)}) — CVE Fix Report</h1>
    <p class="subtitle">Generated {esc(generated)} · linuxtrek.com</p>

    <div class="stats">
      <div class="stat accent"><div class="num">{cve_count}</div><div class="label">CVEs checked</div></div>
      <div class="stat green"><div class="num">{len(unique_cves_matched)}</div><div class="label">CVEs matched</div></div>
      <div class="stat"><div class="num">{len(rows)}</div><div class="label">Package builds</div></div>
      <div class="stat"><div class="num">{len(unique_elsas)}</div><div class="label">Unique ELSAs</div></div>
      <div class="stat amber"><div class="num">{len(unavailable_cves)}</div><div class="label">Unavailable</div></div>
      <div class="stat red"><div class="num">{len(invalid_cves)}</div><div class="label">Invalid IDs</div></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Base Package</th>
          <th>Version</th>
          <th>ELSAs</th>
          <th>CVEs</th>
        </tr>
      </thead>
      <tbody>
{table_rows}
      </tbody>
    </table>

    <div class="footer-notes">
      <h2>Skipped — invalid CVE ID format</h2>
      <p>{id_list(invalid_cves, "elsa")}</p>
      <h2>Not available / not accessible</h2>
      <p>{id_list(unavailable_cves, "elsa")}</p>
    </div>

    <footer>Finished in {elapsed:.2f} seconds.</footer>
  </div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Fetch Oracle Linux ELSA packages for CVEs")
    parser.add_argument("--cve", help="Comma-separated CVE IDs (e.g. CVE-2023-22024,CVE-2023-22025)")
    parser.add_argument("--cve-file", help="Path to text file containing CVE IDs (one per line)")
    parser.add_argument("--version", required=True, help="Oracle Linux version (e.g. 8, 9, 10)")
    parser.add_argument("--arch", required=True, help="Architecture (e.g. x86_64, aarch64)")
    parser.add_argument("--output-file", help="Write the results to this file instead of stdout")
    parser.add_argument(
        "--format", choices=["text", "json", "csv", "html"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color in text output (auto-disabled when not a terminal or --output-file is used)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.2,
        help="Delay in seconds between processing each CVE, to be polite to the server (default: 0.2)"
    )
    parser.add_argument(
        "--max-workers", type=int, default=8,
        help="Max concurrent requests per CVE when fetching ELSA pages (default: 8)"
    )
    parser.add_argument("--retries", type=int, default=3, help="Max HTTP retries per request (default: 3)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output (errors only)")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s", stream=sys.stderr)

    # Collect and validate CVE IDs
    raw_cves: List[str] = []
    if args.cve:
        raw_cves.extend(c.strip() for c in args.cve.split(",") if c.strip())
    if args.cve_file:
        try:
            with open(args.cve_file) as f:
                raw_cves.extend(line.strip() for line in f if line.strip() and not line.strip().startswith("#"))
        except OSError as e:
            logger.error("Could not read --cve-file %s: %s", args.cve_file, e)
            sys.exit(1)

    if not raw_cves:
        logger.error("No CVE IDs provided. Use --cve or --cve-file.")
        sys.exit(1)

    raw_cves = dedupe_preserve_order(raw_cves)

    cves: List[str] = []
    invalid_cves: List[str] = []
    for cve_id in raw_cves:
        if validate_cve_id(cve_id):
            cves.append(cve_id.upper())
        else:
            invalid_cves.append(cve_id)

    if invalid_cves:
        for bad in invalid_cves:
            logger.warning("Skipping invalid CVE ID format: %s", bad)

    if not cves:
        logger.error("No valid CVE IDs to process after validation.")
        sys.exit(1)

    start_time = time.perf_counter()
    logger.info("Processing %d valid CVE(s) for Oracle Linux %s (%s)...", len(cves), args.version, args.arch)

    base_versions: Dict[str, Dict[str, Dict[str, Set[str]]]] = {}
    unavailable_cves: List[str] = []

    session = build_session(max_retries=args.retries)
    try:
        for i, cve_id in enumerate(cves, start=1):
            logger.info("[%d/%d] Processing %s...", i, len(cves), cve_id)
            elsa_map = get_packages_from_cve(
                session, cve_id, args.version, args.arch,
                delay=args.delay, max_workers=args.max_workers,
            )
            if elsa_map is None:
                logger.info("  %s: CVE page not found or not accessible.", cve_id)
                unavailable_cves.append(cve_id)
            elif elsa_map:
                for elsa_id, packages in sorted(elsa_map.items()):
                    logger.debug("  %s - %s: %d package(s)", cve_id, elsa_id, len(packages))
                    for pkg in packages:
                        base, ver = split_base_version(pkg)
                        base_versions.setdefault(base, {}).setdefault(ver, {'cves': set(), 'elsas': set()})
                        base_versions[base][ver]['cves'].add(cve_id)
                        base_versions[base][ver]['elsas'].add(elsa_id)
            else:
                logger.info("  %s: no packages found for this version/arch.", cve_id)

            if args.delay and i < len(cves):
                time.sleep(args.delay)
    finally:
        session.close()

    elapsed = time.perf_counter() - start_time

    if args.format == "json":
        report = render_json_report(base_versions, unavailable_cves, invalid_cves, elapsed)
    elif args.format == "csv":
        report = render_csv_report(base_versions)
    elif args.format == "html":
        report = render_html_report(
            base_versions, unavailable_cves, invalid_cves, elapsed,
            ol_version=args.version, arch=args.arch, cve_count=len(cves),
        )
    else:
        color_enabled = (not args.no_color) and (not args.output_file) and sys.stdout.isatty()
        report = render_text_report(
            base_versions, unavailable_cves, invalid_cves, elapsed,
            ol_version=args.version, arch=args.arch, cve_count=len(cves),
            color=Colors(enabled=color_enabled),
        )

    if args.output_file:
        with open(args.output_file, "w") as out_file:
            out_file.write(report)
        logger.info("Results written to %s", args.output_file)
        logger.info("Finished in %.2f seconds.", elapsed)
    else:
        print(report)


if __name__ == "__main__":
    main()
