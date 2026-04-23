Oracle Linux CVE Fix Fetcher
--

Fetch updated kernel packages from Oracle Linux ELSA advisories for specified CVE IDs, Oracle Linux version, and architecture, skipping .src.rpm files.

Dependencies:
--
  pip install requests beautifulsoup4

Usage examples:
--
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024 --version 9 --arch x86_64
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024,CVE-2023-22025 --version 9 --arch x86_64
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 9 --arch aarch64 --output-file report.txt
