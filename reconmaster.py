#!/usr/bin/env python3
import os
import argparse
import subprocess
import concurrent.futures
import json
import time
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Optional
from tqdm import tqdm
import yaml
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('reconmaster.log'),
        logging.StreamHandler()
    ]
)

console = Console()

class Config:
    def __init__(self):
        self.config_file = Path.home() / '.reconmaster' / 'config.yaml'
        self.config = self._load_config()
        
    def _load_config(self) -> dict:
        """Load configuration from YAML file"""
        if not self.config_file.exists():
            return self._create_default_config()
            
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return self._create_default_config()
            
    def _create_default_config(self) -> dict:
        """Create default configuration"""
        default_config = {
            'api_keys': {
                'shodan': '',
                'virustotal': '',
                'securitytrails': '',
                'censys': ''
            },
            'tools': {
                'subfinder': '/usr/local/bin/subfinder',
                'assetfinder': '/usr/local/bin/assetfinder',
                'amass': '/usr/local/bin/amass',
                'httpx': '/usr/local/bin/httpx',
                'nmap': '/usr/bin/nmap',
                'ffuf': '/usr/local/bin/ffuf',
                'gowitness': '/usr/local/bin/gowitness',
                'katana': '/usr/local/bin/katana',
                'arjun': '/usr/local/bin/arjun'
            },
            'wordlists': {
                'subdomains': '/usr/share/wordlists/subdomains.txt',
                'directories': '/usr/share/wordlists/directory-list.txt',
                'parameters': '/usr/share/wordlists/parameter-names.txt'
            },
            'proxy': {
                'enabled': False,
                'http': '',
                'https': ''
            },
            'threads': 10,
            'timeout': 30
        }
        
        # Create config directory if it doesn't exist
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Save default config
        with open(self.config_file, 'w') as f:
            yaml.dump(default_config, f)
            
        return default_config
        
    def get_api_key(self, service: str) -> str:
        """Get API key for a service"""
        return self.config['api_keys'].get(service, '')
        
    def get_tool_path(self, tool: str) -> str:
        """Get path for a tool"""
        return self.config['tools'].get(tool, '')
        
    def get_wordlist(self, type: str) -> str:
        """Get path for a wordlist"""
        return self.config['wordlists'].get(type, '')
        
    def get_proxy(self) -> dict:
        """Get proxy configuration"""
        return self.config['proxy']
        
    def get_threads(self) -> int:
        """Get number of threads"""
        return self.config['threads']
        
    def get_timeout(self) -> int:
        """Get timeout value"""
        return self.config['timeout']

class ReconMaster:
    def __init__(self, target: str, output_dir: str, threads: int = 10, wordlist: Optional[str] = None):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = output_dir
        self.output_dir = os.path.join(output_dir, f"{target}_{self.timestamp}")
        self.config = Config()
        self.threads = threads or self.config.get_threads()
        self.subdomains: Set[str] = set()
        self.live_domains: Set[str] = set()
        self.urls: Set[str] = set()
        self.js_files: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.parameters: Set[str] = set()
        self.tech_stack: Dict[str, List[str]] = {}
        self.takeovers: List[str] = []
        self.broken_links: List[str] = []
        self.vulnerabilities: List[Dict] = []
        self.ports: Dict[str, List[int]] = {}
        self.services: Dict[str, Dict] = {}
        
        # Use provided wordlist or default from config
        self.wordlist = wordlist if wordlist else self.config.get_wordlist('subdomains')
        
        # Create output directory structure
        self.create_dirs()
        
        # Setup proxy if enabled
        self.proxy = self.config.get_proxy()
        if self.proxy['enabled']:
            os.environ['HTTP_PROXY'] = self.proxy['http']
            os.environ['HTTPS_PROXY'] = self.proxy['https']
            
    def create_dirs(self):
        """Create directory structure for outputs"""
        dirs = [
            self.output_dir,
            f"{self.output_dir}/subdomains",
            f"{self.output_dir}/screenshots",
            f"{self.output_dir}/endpoints",
            f"{self.output_dir}/js",
            f"{self.output_dir}/params",
            f"{self.output_dir}/reports",
            f"{self.output_dir}/vulnerabilities",
            f"{self.output_dir}/tech_stack",
            f"{self.output_dir}/ports"
        ]
        
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
            
        console.print(f"[green][+] Created output directory structure at {self.output_dir}[/green]")
        
    def run_command(self, command: str, description: str = "") -> bool:
        """Run a command with progress tracking"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task(description, total=100)
                
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        progress.update(task, advance=1)
                        
                return_code = process.poll()
                if return_code != 0:
                    error = process.stderr.read()
                    console.print(f"[red][!] Error running command: {error}[/red]")
                    return False
                return True
                
        except Exception as e:
            console.print(f"[red][!] Exception running command: {e}[/red]")
            return False
            
    def passive_subdomain_enum(self):
        """Perform passive subdomain enumeration with improved tools"""
        console.print(f"\n[cyan][+] Starting passive subdomain enumeration for {self.target}[/cyan]")
        
        tools = {
            'subfinder': f"{self.config.get_tool_path('subfinder')} -d {self.target} -o {self.output_dir}/subdomains/subfinder.txt",
            'assetfinder': f"{self.config.get_tool_path('assetfinder')} --subs-only {self.target} > {self.output_dir}/subdomains/assetfinder.txt",
            'amass': f"{self.config.get_tool_path('amass')} enum -passive -d {self.target} -o {self.output_dir}/subdomains/amass.txt"
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for tool, cmd in tools.items():
                futures.append(executor.submit(self.run_command, cmd, f"Running {tool}..."))
                
            for future in concurrent.futures.as_completed(futures):
                if not future.result():
                    console.print("[yellow][!] Some tools failed during passive enumeration[/yellow]")
                    
        # Combine results
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_passive.txt")
        subprocess.run(f"cat {self.output_dir}/subdomains/*.txt | sort -u > {all_subdomains}", shell=True)
        
        # Load subdomains
        try:
            with open(all_subdomains, 'r') as f:
                self.subdomains = set([line.strip() for line in f])
            console.print(f"[green][+] Found {len(self.subdomains)} unique subdomains via passive enumeration[/green]")
        except FileNotFoundError:
            console.print("[red][!] No subdomains found in passive enumeration[/red]")
            
        return self.subdomains
    
    def active_subdomain_enum(self):
        """Perform active subdomain enumeration using brute force with improved tools"""
        console.print(f"\n[cyan][+] Starting active subdomain enumeration for {self.target}[/cyan]")
        
        # Use ffuf for brute forcing subdomains
        ffuf_output = os.path.join(self.output_dir, "subdomains", "ffuf_brute.json")
        console.print(f"[*] Running ffuf with wordlist {self.wordlist}...")
        
        cmd = f"{self.config.get_tool_path('ffuf')} -u http://FUZZ.{self.target} -w {self.wordlist} -o {ffuf_output} -of json -s"
        if not self.run_command(cmd, "Brute forcing subdomains..."):
            console.print("[red][!] Failed to run ffuf[/red]")
            return self.subdomains
        
        # Process ffuf results
        try:
            with open(ffuf_output, 'r') as f:
                ffuf_data = json.load(f)
                for result in ffuf_data.get('results', []):
                    if 'input' in result and 'FUZZ' in result['input']:
                        subdomain = f"{result['input']['FUZZ']}.{self.target}"
                        self.subdomains.add(subdomain)
                        
            # Update all subdomains file
            all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
            with open(all_subdomains, 'w') as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
                    
            console.print(f"[green][+] Total unique subdomains after brute forcing: {len(self.subdomains)}[/green]")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            console.print(f"[red][!] Error processing ffuf results: {e}[/red]")
            
        return self.subdomains
    
    def resolve_live_domains(self):
        """Resolve live domains using httpx with improved functionality"""
        console.print("\n[cyan][+] Resolving live domains with httpx[/cyan]")
        
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        
        # First ensure we have the combined subdomain list
        if not os.path.exists(all_subdomains):
            with open(all_subdomains, 'w') as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
        
        # Run httpx with additional options
        cmd = (
            f"{self.config.get_tool_path('httpx')} -l {all_subdomains} "
            f"-o {live_domains_file} -status-code -title -tech-detect "
            f"-follow-redirects -silent -timeout {self.config.get_timeout()} "
            f"-threads {self.threads}"
        )
        
        if not self.run_command(cmd, "Resolving live domains..."):
            console.print("[red][!] Failed to run httpx[/red]")
            return self.live_domains
        
        # Load live domains and tech stack
        try:
            with open(live_domains_file, 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(' ')
                        domain = parts[0]
                        self.live_domains.add(domain)
                        
                        # Extract tech stack if available
                        if len(parts) > 2:
                            tech = parts[2:]
                            self.tech_stack[domain] = tech
                            
            console.print(f"[green][+] Found {len(self.live_domains)} live domains[/green]")
            
            # Save tech stack information
            tech_stack_file = os.path.join(self.output_dir, "tech_stack", "tech_stack.json")
            with open(tech_stack_file, 'w') as f:
                json.dump(self.tech_stack, f, indent=2)
                
        except FileNotFoundError:
            console.print("[red][!] No live domains found[/red]")
            
        return self.live_domains
    
    def take_screenshots(self):
        """Take screenshots of live domains using gowitness with improved functionality"""
        console.print("\n[cyan][+] Taking screenshots with gowitness[/cyan]")
        
        if not self.live_domains:
            console.print("[yellow][!] No live domains to screenshot. Run resolve_live_domains first.[/yellow]")
            return
        
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        screenshots_dir = os.path.join(self.output_dir, "screenshots")
        
        # Run gowitness with additional options
        cmd = (
            f"{self.config.get_tool_path('gowitness')} file -f {live_domains_file} "
            f"-P {screenshots_dir} --no-http --threads {self.threads} "
            f"--timeout {self.config.get_timeout()}"
        )
        
        if not self.run_command(cmd, "Taking screenshots..."):
            console.print("[red][!] Failed to run gowitness[/red]")
            return
            
        console.print(f"[green][+] Screenshots saved to {screenshots_dir}[/green]")
    
    def scan_for_takeovers(self):
        """Scan for subdomain takeovers using subzy with improved functionality"""
        console.print("\n[cyan][+] Scanning for subdomain takeovers with subzy[/cyan]")
        
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        takeovers_file = os.path.join(self.output_dir, "subdomains", "takeovers.txt")
        
        # Run subzy with additional options
        cmd = (
            f"subzy run --targets {all_subdomains} --output {takeovers_file} "
            f"--threads {self.threads} --timeout {self.config.get_timeout()}"
        )
        
        if not self.run_command(cmd, "Scanning for takeovers..."):
            console.print("[red][!] Failed to run subzy[/red]")
            return
        
        # Check results
        try:
            with open(takeovers_file, 'r') as f:
                self.takeovers = [line.strip() for line in f if line.strip()]
            if self.takeovers:
                console.print(f"[yellow][+] Found {len(self.takeovers)} potential subdomain takeovers![/yellow]")
                for takeover in self.takeovers:
                    console.print(f"[yellow]  - {takeover}[/yellow]")
            else:
                console.print("[green][+] No subdomain takeovers found[/green]")
        except FileNotFoundError:
            console.print("[red][!] No takeover results found[/red]")
    
    def crawl_endpoints(self):
        """Crawl endpoints using katana with improved functionality"""
        console.print("\n[cyan][+] Crawling endpoints with katana[/cyan]")
        
        if not self.live_domains:
            console.print("[yellow][!] No live domains for crawling. Run resolve_live_domains first.[/yellow]")
            return
        
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        urls_file = os.path.join(self.output_dir, "endpoints", "urls.txt")
        js_files = os.path.join(self.output_dir, "js", "js_files.txt")
        
        # Run katana with additional options
        cmd = (
            f"{self.config.get_tool_path('katana')} -list {live_domains_file} "
            f"-jc -o {urls_file} -silent -timeout {self.config.get_timeout()} "
            f"-threads {self.threads}"
        )
        
        if not self.run_command(cmd, "Crawling endpoints..."):
            console.print("[red][!] Failed to run katana[/red]")
            return
        
        # Extract JS files
        console.print("[*] Extracting JavaScript files...")
        cmd = f"cat {urls_file} | grep '\.js$' > {js_files}"
        subprocess.run(cmd, shell=True)
        
        # Run LinkFinder on JS files for endpoint discovery
        console.print("[*] Running LinkFinder on JS files...")
        endpoints_file = os.path.join(self.output_dir, "endpoints", "js_endpoints.txt")
        
        # Process JS files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            with open(js_files, 'r') as f:
                for url in f:
                    url = url.strip()
                    if url:
                        cmd = f"python3 /path/to/LinkFinder/linkfinder.py -i \"{url}\" -o cli >> {endpoints_file}"
                        futures.append(executor.submit(self.run_command, cmd, f"Analyzing {url}..."))
                        
            for future in concurrent.futures.as_completed(futures):
                if not future.result():
                    console.print("[yellow][!] Some JS files failed to analyze[/yellow]")
        
        # Load results
        try:
            with open(urls_file, 'r') as f:
                self.urls = set([line.strip() for line in f])
            with open(js_files, 'r') as f:
                self.js_files = set([line.strip() for line in f])
            console.print(f"[green][+] Discovered {len(self.urls)} URLs and {len(self.js_files)} JavaScript files[/green]")
        except FileNotFoundError:
            console.print("[red][!] Issue loading crawled endpoints[/red]")
    
    def directory_bruteforce(self):
        """Brute force directories using ffuf with improved functionality"""
        console.print("\n[cyan][+] Brute forcing directories with ffuf[/cyan]")
        
        if not self.live_domains:
            console.print("[yellow][!] No live domains for directory brute forcing. Run resolve_live_domains first.[/yellow]")
            return
        
        # Using a smaller list of domains for dir bruteforcing to avoid excessive time
        sample_domains = list(self.live_domains)[:5] if len(self.live_domains) > 5 else list(self.live_domains)
        
        wordlist = self.config.get_wordlist('directories')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for domain in sample_domains:
                output_file = os.path.join(self.output_dir, "endpoints", f"{domain.replace('://', '_').replace('.', '_')}_dirs.json")
                console.print(f"[*] Brute forcing directories for {domain}...")
                
                cmd = (
                    f"{self.config.get_tool_path('ffuf')} -u {domain}/FUZZ -w {wordlist} "
                    f"-mc 200,204,301,302,307,401,403 -o {output_file} -of json -s "
                    f"-timeout {self.config.get_timeout()}"
                )
                
                futures.append(executor.submit(self.run_command, cmd, f"Brute forcing {domain}..."))
                
            for future in concurrent.futures.as_completed(futures):
                if not future.result():
                    console.print("[yellow][!] Some domains failed during directory brute forcing[/yellow]")
                    
        console.print("[green][+] Directory brute forcing completed[/green]")
    
    def find_parameters(self):
        """Find parameters using Arjun with improved functionality"""
        console.print("\n[cyan][+] Finding parameters with Arjun[/cyan]")
        
        endpoints_file = os.path.join(self.output_dir, "endpoints", "urls.txt")
        if not os.path.exists(endpoints_file):
            console.print("[yellow][!] No endpoints found for parameter discovery. Run crawl_endpoints first.[/yellow]")
            return
        
        # Sample a few URLs to avoid excessive time
        with open(endpoints_file, 'r') as f:
            urls = [line.strip() for line in f][:20]  # Limit to 20 URLs
        
        params_file = os.path.join(self.output_dir, "params", "parameters.txt")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for url in urls:
                console.print(f"[*] Finding parameters for {url}...")
                cmd = (
                    f"{self.config.get_tool_path('arjun')} -u {url} -oT {params_file} "
                    f"--passive -t {self.threads} --timeout {self.config.get_timeout()}"
                )
                futures.append(executor.submit(self.run_command, cmd, f"Analyzing {url}..."))
                
            for future in concurrent.futures.as_completed(futures):
                if not future.result():
                    console.print("[yellow][!] Some URLs failed during parameter discovery[/yellow]")
        
        console.print("[green][+] Parameter finding completed[/green]")
    
    def check_broken_links(self):
        """Check for broken link hijacking opportunities with improved functionality"""
        console.print("\n[cyan][+] Checking for broken links[/cyan]")
        
        if not self.live_domains:
            console.print("[yellow][!] No live domains for broken link checking. Run resolve_live_domains first.[/yellow]")
            return
        
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        broken_links_file = os.path.join(self.output_dir, "reports", "broken_links.txt")
        
        # Run socialhunter with additional options
        cmd = (
            f"socialhunter -l {live_domains_file} -o {broken_links_file} "
            f"--threads {self.threads} --timeout {self.config.get_timeout()}"
        )
        
        if not self.run_command(cmd, "Checking for broken links..."):
            console.print("[red][!] Failed to run socialhunter[/red]")
            return
        
        # Check results
        try:
            with open(broken_links_file, 'r') as f:
                self.broken_links = [line.strip() for line in f if line.strip()]
            if self.broken_links:
                console.print(f"[yellow][+] Found {len(self.broken_links)} potential broken links[/yellow]")
                for link in self.broken_links[:10]:  # Show first 10 broken links
                    console.print(f"[yellow]  - {link}[/yellow]")
                if len(self.broken_links) > 10:
                    console.print(f"[yellow]  - ... and {len(self.broken_links) - 10} more[/yellow]")
            else:
                console.print("[green][+] No broken links found[/green]")
        except FileNotFoundError:
            console.print("[red][!] No broken link results found[/red]")
    
    def port_scan(self):
        """Scan ports using nmap with improved functionality"""
        console.print("\n[cyan][+] Scanning ports with nmap[/cyan]")
        
        if not self.live_domains:
            console.print("[yellow][!] No live domains for port scanning. Run resolve_live_domains first.[/yellow]")
            return
        
        # Sample domains for port scanning to avoid excessive time
        sample_domains = list(self.live_domains)[:5] if len(self.live_domains) > 5 else list(self.live_domains)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for domain in sample_domains:
                # Extract host from URL
                host = domain.split("://")[1].split("/")[0]
                output_file = os.path.join(self.output_dir, "ports", f"{host}_nmap.txt")
                console.print(f"[*] Scanning ports for {host}...")
                
                cmd = (
                    f"{self.config.get_tool_path('nmap')} -p- -T4 -sC -sV {host} "
                    f"-o {output_file} --min-rate 1000 --max-retries 2"
                )
                
                futures.append(executor.submit(self.run_command, cmd, f"Scanning {host}..."))
                
            for future in concurrent.futures.as_completed(futures):
                if not future.result():
                    console.print("[yellow][!] Some hosts failed during port scanning[/yellow]")
        
        # Process nmap results
        for domain in sample_domains:
            host = domain.split("://")[1].split("/")[0]
            output_file = os.path.join(self.output_dir, "ports", f"{host}_nmap.txt")
            
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    # Extract open ports
                    ports = []
                    for line in content.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            port = int(line.split('/')[0])
                            ports.append(port)
                    self.ports[host] = ports
                    
                    # Extract services
                    services = {}
                    for line in content.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            parts = line.split()
                            port = int(parts[0].split('/')[0])
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                            services[port] = {'service': service, 'version': version}
                    self.services[host] = services
                    
            except FileNotFoundError:
                console.print(f"[red][!] No nmap results found for {host}[/red]")
        
        console.print("[green][+] Port scanning completed[/green]")
    
    def generate_report(self):
        """Generate a comprehensive report with improved formatting"""
        console.print("\n[cyan][+] Generating comprehensive report[/cyan]")
        
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
            
            # Add tech stack information
            if self.tech_stack:
                f.write("## Technology Stack\n\n")
                for domain, tech in self.tech_stack.items():
                    f.write(f"### {domain}\n")
                    for t in tech:
                        f.write(f"- {t}\n")
                    f.write("\n")
            
            # Add port scan results
            if self.ports:
                f.write("## Port Scan Results\n\n")
                for host, ports in self.ports.items():
                    f.write(f"### {host}\n")
                    f.write("#### Open Ports\n")
                    for port in ports:
                        service = self.services[host].get(port, {})
                        service_name = service.get('service', 'unknown')
                        version = service.get('version', '')
                        f.write(f"- {port}/tcp - {service_name} {version}\n")
                    f.write("\n")
            
            f.write("## Next Steps\n\n")
            f.write("1. Review subdomain takeover opportunities\n")
            f.write("2. Test discovered endpoints for vulnerabilities\n")
            f.write("3. Analyze JavaScript files for sensitive information\n")
            f.write("4. Test parameters for injection vulnerabilities\n")
            f.write("5. Check broken links for potential hijacking\n")
            f.write("6. Investigate open ports and services\n")
            f.write("7. Review technology stack for known vulnerabilities\n")
            
        console.print(f"[green][+] Report generated: {report_file}[/green]")
        
        # Display summary in console
        table = Table(title="Reconnaissance Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        
        table.add_row("Subdomains", str(len(self.subdomains)))
        table.add_row("Live Domains", str(len(self.live_domains)))
        table.add_row("Takeovers", str(len(self.takeovers)))
        table.add_row("URLs", str(len(self.urls)))
        table.add_row("JS Files", str(len(self.js_files)))
        table.add_row("Broken Links", str(len(self.broken_links)))
        
        console.print(table)
    
    def run_all(self):
        """Run the complete reconnaissance process with improved progress tracking"""
        start_time = time.time()
        console.print(Panel.fit(
            f"Starting comprehensive reconnaissance for {self.target}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="ReconMaster",
            border_style="cyan"
        ))
        
        # Execute all recon steps
        steps = [
            ("Passive Subdomain Enumeration", self.passive_subdomain_enum),
            ("Active Subdomain Enumeration", self.active_subdomain_enum),
            ("Resolving Live Domains", self.resolve_live_domains),
            ("Taking Screenshots", self.take_screenshots),
            ("Scanning for Takeovers", self.scan_for_takeovers),
            ("Crawling Endpoints", self.crawl_endpoints),
            ("Directory Brute Forcing", self.directory_bruteforce),
            ("Finding Parameters", self.find_parameters),
            ("Checking Broken Links", self.check_broken_links),
            ("Port Scanning", self.port_scan),
            ("Generating Report", self.generate_report)
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Overall Progress", total=len(steps))
            
            for name, step in steps:
                progress.update(task, description=f"Running {name}...")
                step()
                progress.update(task, advance=1)
        
        end_time = time.time()
        duration = end_time - start_time
        
        console.print(Panel.fit(
            f"Reconnaissance completed in {duration:.2f} seconds\n"
            f"Results saved to: {self.output_dir}",
            title="ReconMaster",
            border_style="green"
        ))


def main():
    parser = argparse.ArgumentParser(description="ReconMaster: Automated Reconnaissance Framework")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    parser.add_argument("-o", "--output", default="./recon_results", help="Output directory for results")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads to use")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for subdomain brute forcing")
    parser.add_argument("--passive-only", action="store_true", help="Only perform passive reconnaissance")
    parser.add_argument("--config", help="Path to custom configuration file")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, help="Timeout for requests in seconds")
    
    args = parser.parse_args()
    
    # Validate domain
    if not args.domain:
        console.print("[red][!] Target domain is required[/red]")
        sys.exit(1)
    
    # Create ReconMaster instance
    recon = ReconMaster(
        target=args.domain,
        output_dir=args.output,
        threads=args.threads,
        wordlist=args.wordlist
    )
    
    # Override config if specified
    if args.config:
        recon.config.config_file = Path(args.config)
        recon.config.config = recon.config._load_config()
    
    # Override proxy if specified
    if args.proxy:
        recon.proxy = {
            'enabled': True,
            'http': args.proxy,
            'https': args.proxy
        }
        os.environ['HTTP_PROXY'] = args.proxy
        os.environ['HTTPS_PROXY'] = args.proxy
    
    # Override timeout if specified
    if args.timeout:
        recon.config.config['timeout'] = args.timeout
    
    if args.passive_only:
        recon.passive_subdomain_enum()
        recon.resolve_live_domains()
        recon.take_screenshots()
    else:
        recon.run_all()


if __name__ == "__main__":
    main()
