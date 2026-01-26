# CVEye

CVEye is a **Python-based vulnerability intelligence tool** that aggregates, summarizes, and displays CVE information, exploits, and MITRE ATT&CK techniques. 

---

## Features

- Aggregates CVE data from **NVD**, **MSRC**, and **Exploit-DB**
- Displays CVE ID, description, vector string, and base score
- Truncates long descriptions for clean CLI output
- Maps vulnerabilities to **MITRE ATT&CK techniques**
- Produces readable, terminal-friendly tables
- Designed for scripting and automation

## Installation

```bash
git clone https://github.com/yourusername/CVEye.git
cd CVEye
pip install -r requirements.txt
```

## Datasets

- [Exploit DB](https://gitlab.com/exploit-database/exploitdb/-/blob/main/files_exploits.csv?ref_type=heads)
- [Known Exploited Vulnerabilities (KEV)](https://zenodo.org/records/16747173?utm_source=chatgpt.com)
- [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)


