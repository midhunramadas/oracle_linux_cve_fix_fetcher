Oracle Linux CVE Fix Fetcher
--

Fetch updated packages from Oracle Linux ELSA advisories for specified CVE IDs, Oracle Linux version, and architecture.

Dependencies:
--
```
  pip install requests beautifulsoup4
```
Usage
-----
```
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024 --version 9 --arch x86_64
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024,CVE-2023-22025 --version 9 --arch x86_64
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 9 --arch aarch64 --output-file report.txt
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 9 --arch x86_64 --format json --output-file report.json
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024 --version 9 --arch x86_64 --verbose --delay 0.5
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 8 --arch x86_64 --format html --output-file report.html
```
Arguments:
-----
```
usage: oracle_linux_cve_fix_fetcher.py [-h] [--cve CVE] [--cve-file CVE_FILE]
                                       --version VERSION --arch ARCH
                                       [--output-file OUTPUT_FILE]
                                       [--format {text,json,csv,html}]
                                       [--no-color] [--delay DELAY]
                                       [--max-workers MAX_WORKERS]
                                       [--retries RETRIES] [-v] [-q]

```


Usage examples:
--
```
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024 --version 9 --arch x86_64
```
```  
  python oracle_linux_cve_fix_fetcher.py --cve CVE-2023-22024,CVE-2023-22025 --version 9 --arch x86_64
```
``` 
  python oracle_linux_cve_fix_fetcher.py --cve-file cves.txt --version 9 --arch aarch64 --output-file report.txt
```

