#!/usr/bin/env python3
"""
oracle_linux_cve_fix_fetcher.py

Fetch updated kernel packages from Oracle Linux ELSA advisories for specified CVE IDs, Oracle Linux version, and architecture.

Dependencies:
  pip install requests beautifulsoup4

Usage examples:
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024 --version 9 --arch x86_64
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024,CVE-2023-22025 --version 9 --arch x86_64
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 9 --arch aarch64 --output-file report.txt
"""

import argparse
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

CVE_BASE_URL = "https://linux.oracle.com/cve/"

def fetch_page(session: requests.Session, url: str) -> str:
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text

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
    session: requests.Session, cve_id: str, version: str, arch: str
) -> Optional[Dict[str, List[str]]]:
    try:
        links = find_elsa_links(session, cve_id, version)
    except requests.exceptions.HTTPError:
        return None
    results: Dict[str, List[str]] = {}
    if not links:
        return results
    with ThreadPoolExecutor(max_workers=min(8, len(links))) as executor:
        future_to_link = {
            executor.submit(fetch_page, session, link): link for link in links
        }
        for future in as_completed(future_to_link):
            link = future_to_link[future]
            try:
                html = future.result()
            except Exception:
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
    two hyphen-separated segments (before .rpm) are version and release;
    everything before that is the base package name.
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

def main():
    parser = argparse.ArgumentParser(description="Fetch Oracle Linux ELSA packages for CVEs")
    parser.add_argument("--cve", help="Comma-separated CVE IDs (e.g. CVE-2023-22024,CVE-2023-22025)")
    parser.add_argument("--cve-file", help="Path to text file containing CVE IDs (one per line)")
    parser.add_argument("--version", required=True, help="Oracle Linux version (e.g. 8, 9, 10)")
    parser.add_argument("--arch", required=True, help="Architecture (e.g. x86_64, aarch64)")
    parser.add_argument("--output-file", help="Write the results to this file instead of stdout")
    args = parser.parse_args()

    # Collect CVE IDs
    cves: List[str] = []
    if args.cve:
        for cve_id in args.cve.split(","):
            cve_id = cve_id.strip()
            if cve_id:
                cves.append(cve_id)
    if args.cve_file:
        with open(args.cve_file) as f:
            cves.extend(line.strip() for line in f if line.strip())
    if not cves:
        print("No CVE IDs provided. Use --cve or --cve-file.")
        return

    start_time = time.perf_counter()
    print(f"Starting processing of {len(cves)} CVE(s) for Oracle Linux {args.version} ({args.arch})...")

    output_lines: List[str] = []
    summary_packages: List[str] = []
    unavailable_cves: List[str] = []

    with requests.Session() as session:
        for cve_id in cves:
            output_lines.append(f"\nProcessing {cve_id} for Oracle Linux {args.version} ({args.arch})...")
            elsa_map = get_packages_from_cve(session, cve_id, args.version, args.arch)

            if elsa_map is None:
                output_lines.append("  CVE page not found or not accessible.")
                unavailable_cves.append(cve_id)
            elif elsa_map:
                for elsa_id, packages in sorted(elsa_map.items()):
                    output_lines.append(f"  {cve_id} – {elsa_id}")
                    for pkg in packages:
                        output_lines.append(f"    {pkg}")
                    summary_packages.extend(packages)
            else:
                output_lines.append("  No packages found (ELSA not found or no matches for version/arch).")

    # Build summary: highest version of each base package
    if summary_packages:
        highest_versions: Dict[str, Tuple[str, str]] = {}
        for pkg in summary_packages:
            base, ver_rel = split_base_version(pkg)
            if base not in highest_versions or ver_rel > highest_versions[base][1]:
                highest_versions[base] = (pkg, ver_rel)
        final_list = sorted(v[0] for v in highest_versions.values())
        output_lines.append("\n" + "="*60)
        output_lines.append("Summary of fixed RPMs (highest versions only):")
        output_lines.append("="*60)
        for p in final_list:
            output_lines.append(f"  {p}")
        output_lines.append("="*60)
    else:
        output_lines.append("\n" + "="*60)
        output_lines.append("Summary: no packages found for the given CVEs/version/arch.")
        output_lines.append("="*60)

    # Summary of unavailable CVEs
    if unavailable_cves:
        output_lines.append("\n" + "="*60)
        output_lines.append("Summary of CVE IDs not available or not accessible:")
        output_lines.append("="*60)
        for cve in sorted(unavailable_cves):
            output_lines.append(f"  {cve}")
        output_lines.append("="*60)

    elapsed = time.perf_counter() - start_time
    output_lines.append(f"\nFinished in {elapsed:.2f} seconds.")

    if args.output_file:
        with open(args.output_file, "w") as out_file:
            out_file.write("\n".join(output_lines))
        print(f"Results written to {args.output_file}")
        # Also print time to console along with file notification
        print(f"Finished in {elapsed:.2f} seconds.")
    else:
        print("\n".join(output_lines))

if __name__ == "__main__":
    main()
