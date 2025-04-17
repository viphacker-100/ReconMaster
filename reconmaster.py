#!/usr/bin/env python3
import os
import argparse
import subprocess
import concurrent.futures
import json
import time
from datetime import datetime

class ReconMaster:
    def __init__(self, target, output_dir, threads=10, wordlist=None):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = output_dir
        self.output_dir = os.path.join(output_dir, f"{target}_{self.timestamp}")
        self.threads = threads
        self.subdomains = set()
        self.live_domains = set()
        self.urls = set()
        self.js_files = set()
        self.endpoints = set()
        self.parameters = set()
        self.tech_stack = {}
        self.takeovers = []
        self.broken_links = []

        # Default wordlist if none specified
        self.wordlist = wordlist if wordlist else "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt"
        
        # Create output directory structure
        self.create_dirs()
        
    def create_dirs(self):
        """Create directory structure for outputs"""
        dirs = [
            self.output_dir,
            f"{self.output_dir}/subdomains",
            f"{self.output_dir}/screenshots",
            f"{self.output_dir}/endpoints",
            f"{self.output_dir}/js",
            f"{self.output_dir}/params",
            f"{self.output_dir}/reports"
        ]
        
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
            
        print(f"[+] Created output directory structure at {self.output_dir}")
        
    def passive_subdomain_enum(self):
        """Perform passive subdomain enumeration"""
        print(f"\n[+] Starting passive subdomain enumeration for {self.target}")
        
        # Subfinder
        subfinder_output = os.path.join(self.output_dir, "subdomains", "subfinder.txt")
        print("[*] Running subfinder...")
        subprocess.run(f"subfinder -d {self.target} -o {subfinder_output}", shell=True)
        
        # Assetfinder
        assetfinder_output = os.path.join(self.output_dir, "subdomains", "assetfinder.txt")
        print("[*] Running assetfinder...")
        subprocess.run(f"assetfinder --subs-only {self.target} > {assetfinder_output}", shell=True)
        
        # Amass passive
        amass_output = os.path.join(self.output_dir, "subdomains", "amass.txt")
        print("[*] Running amass passive...")
        subprocess.run(f"amass enum -passive -d {self.target} -o {amass_output}", shell=True)
        
        # Combine results
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_passive.txt")
        subprocess.run(f"cat {self.output_dir}/subdomains/*.txt | sort -u > {all_subdomains}", shell=True)
        
        # Load subdomains
        try:
            with open(all_subdomains, 'r') as f:
                self.subdomains = set([line.strip() for line in f])
            print(f"[+] Found {len(self.subdomains)} unique subdomains via passive enumeration")
        except FileNotFoundError:
            print("[!] No subdomains found in passive enumeration")
            
        return self.subdomains
    
    def active_subdomain_enum(self):
        """Perform active subdomain enumeration using brute force"""
        print(f"\n[+] Starting active subdomain enumeration for {self.target}")
        
        # Use ffuf for brute forcing subdomains
        ffuf_output = os.path.join(self.output_dir, "subdomains", "ffuf_brute.json")
        print(f"[*] Running ffuf with wordlist {self.wordlist}...")
        
        cmd = f"ffuf -u http://FUZZ.{self.target} -w {self.wordlist} -o {ffuf_output} -of json -s"
        subprocess.run(cmd, shell=True)
        
        # Process ffuf results
        try:
            with open(ffuf_output, 'r') as f:
                ffuf_data = json.load(f)
                for result in ffuf_data.get('results', []):
                    if 'input' in result and 'FUZZ' in result['input']:
                        subdomain = f"{result['input']['FUZZ']}.{self.target}"
                        self.subdomains.add(subdomain)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Error processing ffuf results: {e}")
        
        # Update all subdomains file
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        with open(all_subdomains, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
                
        print(f"[+] Total unique subdomains after brute forcing: {len(self.subdomains)}")
        return self.subdomains
    
    def resolve_live_domains(self):
        """Resolve live domains using httpx"""
        print("\n[+] Resolving live domains with httpx")
        
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        
        # First ensure we have the combined subdomain list
        if not os.path.exists(all_subdomains):
            with open(all_subdomains, 'w') as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
        
        # Run httpx
        cmd = f"httpx -l {all_subdomains} -o {live_domains_file} -status-code -title -tech-detect -follow-redirects"
        subprocess.run(cmd, shell=True)
        
        # Load live domains
        try:
            with open(live_domains_file, 'r') as f:
                for line in f:
                    if line.strip():
                        domain = line.strip().split(' ')[0]
                        self.live_domains.add(domain)
            print(f"[+] Found {len(self.live_domains)} live domains")
        except FileNotFoundError:
            print("[!] No live domains found")
            
        return self.live_domains
    
    def take_screenshots(self):
        """Take screenshots of live domains using gowitness"""
        print("\n[+] Taking screenshots with gowitness")
        
        if not self.live_domains:
            print("[!] No live domains to screenshot. Run resolve_live_domains first.")
            return
        
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        screenshots_dir = os.path.join(self.output_dir, "screenshots")
        
        # Run gowitness
        cmd = f"gowitness file -f {live_domains_file} -P {screenshots_dir} --no-http"
        subprocess.run(cmd, shell=True)
        
        print(f"[+] Screenshots saved to {screenshots_dir}")
    
    def scan_for_takeovers(self):
        """Scan for subdomain takeovers using subzy"""
        print("\n[+] Scanning for subdomain takeovers with subzy")
        
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        takeovers_file = os.path.join(self.output_dir, "subdomains", "takeovers.txt")
        
        # Run subzy
        cmd = f"subzy run --targets {all_subdomains} --output {takeovers_file}"
        subprocess.run(cmd, shell=True)
        
        # Check results
        try:
            with open(takeovers_file, 'r') as f:
                self.takeovers = [line.strip() for line in f if line.strip()]
            if self.takeovers:
                print(f"[+] Found {len(self.takeovers)} potential subdomain takeovers!")
            else:
                print("[+] No subdomain takeovers found")
        except FileNotFoundError:
            print("[+] No subdomain takeovers found")
    
    def crawl_endpoints(self):
        """Crawl endpoints using katana"""
        print("\n[+] Crawling endpoints with katana")
        
        if not self.live_domains:
            print("[!] No live domains for crawling. Run resolve_live_domains first.")
            return
        
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        urls_file = os.path.join(self.output_dir, "endpoints", "urls.txt")
        js_files = os.path.join(self.output_dir, "js", "js_files.txt")
        
        # Run katana to discover URLs
        print("[*] Running katana for URL discovery...")
        cmd = f"katana -list {live_domains_file} -jc -o {urls_file}"
        subprocess.run(cmd, shell=True)
        
        # Extract JS files
        print("[*] Extracting JavaScript files...")
        cmd = f"cat {urls_file} | grep '\.js$' > {js_files}"
        subprocess.run(cmd, shell=True)
        
        # Run LinkFinder on JS files for endpoint discovery
        print("[*] Running LinkFinder on JS files...")
        endpoints_file = os.path.join(self.output_dir, "endpoints", "js_endpoints.txt")
        cmd = f"cat {js_files} | while read url; do python3 /path/to/LinkFinder/linkfinder.py -i \"$url\" -o cli >> {endpoints_file}; done"
        subprocess.run(cmd, shell=True)
        
        # Load results
        try:
            with open(urls_file, 'r') as f:
                self.urls = set([line.strip() for line in f])
            with open(js_files, 'r') as f:
                self.js_files = set([line.strip() for line in f])
            print(f"[+] Discovered {len(self.urls)} URLs and {len(self.js_files)} JavaScript files")
        except FileNotFoundError:
            print("[!] Issue loading crawled endpoints")
    
    def directory_bruteforce(self):
        """Brute force directories using ffuf"""
        print("\n[+] Brute forcing directories with ffuf")
        
        if not self.live_domains:
            print("[!] No live domains for directory brute forcing. Run resolve_live_domains first.")
            return
        
        # Using a smaller list of domains for dir bruteforcing to avoid excessive time
        sample_domains = list(self.live_domains)[:5] if len(self.live_domains) > 5 else list(self.live_domains)
        
        wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        for domain in sample_domains:
            output_file = os.path.join(self.output_dir, "endpoints", f"{domain.replace('://', '_').replace('.', '_')}_dirs.json")
            print(f"[*] Brute forcing directories for {domain}...")
            cmd = f"ffuf -u {domain}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -o {output_file} -of json -s"
            subprocess.run(cmd, shell=True)
            
        print("[+] Directory brute forcing completed")
    
    def find_parameters(self):
        """Find parameters using Arjun"""
        print("\n[+] Finding parameters with Arjun")
        
        endpoints_file = os.path.join(self.output_dir, "endpoints", "urls.txt")
        if not os.path.exists(endpoints_file):
            print("[!] No endpoints found for parameter discovery. Run crawl_endpoints first.")
            return
        
        # Sample a few URLs to avoid excessive time
        with open(endpoints_file, 'r') as f:
            urls = [line.strip() for line in f][:20]  # Limit to 20 URLs
        
        params_file = os.path.join(self.output_dir, "params", "parameters.txt")
        
        for url in urls:
            print(f"[*] Finding parameters for {url}...")
            cmd = f"arjun -u {url} -oT {params_file} --passive -t 10"
            subprocess.run(cmd, shell=True)
        
        print("[+] Parameter finding completed")
    
    def check_broken_links(self):
        """Check for broken link hijacking opportunities"""
        print("\n[+] Checking for broken links with socialhunter")
        
        if not self.live_domains:
            print("[!] No live domains for broken link checking. Run resolve_live_domains first.")
            return
        
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        broken_links_file = os.path.join(self.output_dir, "reports", "broken_links.txt")
        
        # Run socialhunter
        cmd = f"socialhunter -l {live_domains_file} -o {broken_links_file}"
        subprocess.run(cmd, shell=True)
        
        # Check results
        try:
            with open(broken_links_file, 'r') as f:
                self.broken_links = [line.strip() for line in f if line.strip()]
            print(f"[+] Found {len(self.broken_links)} potential broken links")
        except FileNotFoundError:
            print("[+] No broken links found")
    
    def port_scan(self):
        """Scan ports using nmap"""
        print("\n[+] Scanning ports with nmap")
        
        if not self.live_domains:
            print("[!] No live domains for port scanning. Run resolve_live_domains first.")
            return
        
        # Sample domains for port scanning to avoid excessive time
        sample_domains = list(self.live_domains)[:5] if len(self.live_domains) > 5 else list(self.live_domains)
        
        for domain in sample_domains:
            # Extract host from URL
            host = domain.split("://")[1].split("/")[0]
            output_file = os.path.join(self.output_dir, "reports", f"{host}_nmap.txt")
            print(f"[*] Scanning ports for {host}...")
            
            cmd = f"nmap -p- -T4 -sC -sV {host} -o {output_file}"
            subprocess.run(cmd, shell=True)
        
        print("[+] Port scanning completed")
    
    def generate_report(self):
        """Generate a comprehensive report"""
        print("\n[+] Generating comprehensive report")
        
        report_file = os.path.join(self.output_dir, "reports", "summary_report.md")
        
        with open(report_file, 'w') as f:
            f.write(f"# Reconnaissance Report for {self.target}\n\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"- Target: {self.target}\n")
            f.write(f"- Total Subdomains Discovered: {len(self.subdomains)}\n")
            f.write(f"- Live Domains: {len(self.live_domains)}\n")
            f.write(f"- Potential Subdomain Takeovers: {len(self.takeovers)}\n")
            f.write(f"- URLs Discovered: {len(self.urls)}\n")
            f.write(f"- JavaScript Files: {len(self.js_files)}\n")
            f.write(f"- Broken Links: {len(self.broken_links)}\n\n")
            
            # Add subdomain takeovers if any
            if self.takeovers:
                f.write("## Potential Subdomain Takeovers\n\n")
                for takeover in self.takeovers:
                    f.write(f"- {takeover}\n")
                f.write("\n")
            
            # Add broken links if any
            if self.broken_links:
                f.write("## Broken Links\n\n")
                for link in self.broken_links[:20]:  # Limit to 20 to avoid huge reports
                    f.write(f"- {link}\n")
                if len(self.broken_links) > 20:
                    f.write(f"- ... and {len(self.broken_links) - 20} more\n")
                f.write("\n")
            
            f.write("## Next Steps\n\n")
            f.write("1. Review subdomain takeover opportunities\n")
            f.write("2. Test discovered endpoints for vulnerabilities\n")
            f.write("3. Analyze JavaScript files for sensitive information\n")
            f.write("4. Test parameters for injection vulnerabilities\n")
            f.write("5. Check broken links for potential hijacking\n")
            
        print(f"[+] Report generated: {report_file}")
    
    def run_all(self):
        """Run the complete reconnaissance process"""
        start_time = time.time()
        print(f"Starting comprehensive reconnaissance for {self.target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Execute all recon steps
        self.passive_subdomain_enum()
        self.active_subdomain_enum()
        self.resolve_live_domains()
        self.take_screenshots()
        self.scan_for_takeovers()
        self.crawl_endpoints()
        self.directory_bruteforce()
        self.find_parameters()
        self.check_broken_links()
        self.port_scan()
        self.generate_report()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n[+] Reconnaissance completed in {duration:.2f} seconds")
        print(f"[+] Results saved to: {self.output_dir}")


def main():
    parser = argparse.ArgumentParser(description="ReconMaster: Automated Reconnaissance Framework")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    parser.add_argument("-o", "--output", default="./recon_results", help="Output directory for results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for subdomain brute forcing")
    parser.add_argument("--passive-only", action="store_true", help="Only perform passive reconnaissance")
    
    args = parser.parse_args()
    
    recon = ReconMaster(
        target=args.domain,
        output_dir=args.output,
        threads=args.threads,
        wordlist=args.wordlist
    )
    
    if args.passive_only:
        recon.passive_subdomain_enum()
        recon.resolve_live_domains()
        recon.take_screenshots()
    else:
        recon.run_all()


if __name__ == "__main__":
    main()
