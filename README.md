Oracle Linux CVE Fix Fetcher
--

Fetch updated packages from Oracle Linux ELSA advisories for specified CVE IDs, Oracle Linux version, and architecture.

Dependencies:
--
  pip install requests beautifulsoup4

Usage examples:
--
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024 --version 9 --arch x86_64
  
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024,CVE-2023-22025 --version 9 --arch x86_64
  
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 9 --arch aarch64 --output-file report.txt

Options:
-----
  -h, --help                  show this help message and exit
  --cve CVE                   Comma-separated CVE IDs (e.g. CVE-2023-22024,CVE-2023-22025)
  --cve-file CVE_FILE         Path to text file containing CVE IDs (one per line)
  --version VERSION           Oracle Linux version (e.g. 8, 9, 10)
  --arch ARCH                 Architecture (e.g. x86_64, aarch64)
  --output-file OUTPUT_FILE   Write the results to this file instead of stdout
