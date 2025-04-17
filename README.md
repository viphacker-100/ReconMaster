# ReconMaster: Automated Reconnaissance Tool

I've created a comprehensive reconnaissance framework called **ReconMaster** that integrates all the tools you mentioned into a single, streamlined workflow. This tool automates the entire reconnaissance process from subdomain discovery to reporting.

## Features

- **Subdomain Enumeration**:
  - Passive discovery using subfinder, assetfinder, and amass
  - Active brute forcing with ffuf
  
- **Domain Processing**:
  - Live domain filtering with httpx
  - Screenshot capture with gowitness
  - Subdomain takeover checks with subzy
  
- **Content Discovery**:
  - Endpoint crawling with katana
  - JavaScript file extraction
  - Directory brute forcing with ffuf
  - Parameter discovery with arjun
  
- **Security Checks**:
  - Broken link detection with socialhunter
  - Port scanning with nmap
  
- **Reporting**:
  - Comprehensive markdown report generation

## Usage

```bash
git clone https://github.com/viphacker-100/ReconMaster
cd ReconMaster
python3 reconmaster.py -d target.com -o ./recon_results
```

Optional flags:
- `-t, --threads`: Set number of threads (default: 10)
- `-w, --wordlist`: Custom wordlist for subdomain brute forcing
- `--passive-only`: Only perform non-intrusive reconnaissance

## Implementation

The tool is implemented as a Python class that orchestrates the various tools in a logical sequence. It creates a structured output directory for each target and stores all results in an organized manner.
