#!/usr/bin/env python3
import os
import argparse
import subprocess
import concurrent.futures
import json
import time
import shutil
import sys
import logging
import requests
from datetime import datetime
from typing import Set, Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Initialize rich console for better output
console = Console()

@dataclass
class ReconResults:
    """Data class to store reconnaissance results"""
    subdomains: Set[str] = field(default_factory=set)
    live_domains: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    js_files: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    tech_stack: Dict[str, List[str]] = field(default_factory=dict)
    takeovers: List[str] = field(default_factory=list)
    broken_links: List[str] = field(default_factory=list)
    vulnerabilities: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)

class ReconMaster:
    def __init__(self, target: str, output_dir: str, threads: int = 10, 
                 wordlist: Optional[str] = None, verbosity: int = 1):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = output_dir
        self.output_dir = os.path.join(output_dir, f"{target}_{self.timestamp}")
        self.threads = threads
        self.verbosity = verbosity
        self.results = ReconResults()
        
        # Configure logging
        log_level = logging.DEBUG if verbosity > 1 else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"{self.output_dir}_recon.log", mode='w'),
                logging.StreamHandler() if verbosity > 2 else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger("ReconMaster")

        # Create wordlists directory
        wordlist_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists")
        os.makedirs(wordlist_dir, exist_ok=True)
        
        # Download n0kovo subdomains wordlist if not present
        n0kovo_wordlist = os.path.join(wordlist_dir, "n0kovo_subdomains.txt")
        if not os.path.exists(n0kovo_wordlist):
            self.download_wordlist(
                "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_medium.txt",
                n0kovo_wordlist
            )
        
        # Default wordlists with fallbacks
        self.wordlists = {
            "subdomains": self._find_wordlist(
                wordlist,
                [
                    n0kovo_wordlist,
                    "./wordlists/subdomains.txt"
                ]
            ),
            "directories": self._find_wordlist(
                None,
                [
                    "/usr/share/wordlists/dirb/common.txt",
                    "./wordlists/directories.txt"
                ]
            )
        }
        
        # Check for required tools
        self.check_requirements()
        
        # Create output directory structure
        self.create_dirs()
    
    def download_wordlist(self, url: str, output_path: str) -> bool:
        """Download a wordlist from a URL"""
        try:
            console.print(f"[bold yellow]Downloading wordlist from {url}...[/bold yellow]")
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                console.print(f"[green]✓[/green] Wordlist downloaded to {output_path}")
                return True
            else:
                console.print(f"[red]✗[/red] Failed to download wordlist: HTTP {response.status_code}")
                return False
        except Exception as e:
            console.print(f"[red]✗[/red] Error downloading wordlist: {str(e)}")
            return False
            
    def _find_wordlist(self, specified_wordlist: Optional[str], fallbacks: List[str]) -> str:
        """Find and validate a wordlist path with fallbacks"""
        if specified_wordlist and os.path.exists(specified_wordlist):
            return specified_wordlist
            
        for fallback in fallbacks:
            if os.path.exists(fallback):
                return fallback
                
        # Create a minimal default wordlist if nothing is found
        default_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists")
        os.makedirs(default_dir, exist_ok=True)
        
        if "subdomains" in fallbacks[0]:
            default_list = os.path.join(default_dir, "subdomains.txt")
            if not os.path.exists(default_list):
                with open(default_list, 'w') as f:
                    f.write("\n".join(["www", "mail", "dev", "admin", "test", "staging", "prod", 
                                      "api", "portal", "app", "dashboard", "beta", "store", "shop",
                                      "secure", "corporate", "internal", "uat", "qa", "vpn"]))
            return default_list
        else:
            default_list = os.path.join(default_dir, "directories.txt")
            if not os.path.exists(default_list):
                with open(default_list, 'w') as f:
                    f.write("\n".join(["admin", "login", "wp-admin", "backup", "api", "dev", "test",
                                      "dashboard", "portal", "cdn", "static", "assets", "images",
                                      "uploads", "config", "settings", "users", "auth", "wp-content"]))
            return default_list
        
    def check_requirements(self) -> None:
        """Check if required tools are installed"""
        required_tools = {
            "subfinder": "https://github.com/projectdiscovery/subfinder",
            "httpx": "https://github.com/projectdiscovery/httpx",
            "ffuf": "https://github.com/ffuf/ffuf"
        }
        
        optional_tools = {
            "nuclei": "https://github.com/projectdiscovery/nuclei",
            "katana": "https://github.com/projectdiscovery/katana",
            "gowitness": "https://github.com/sensepost/gowitness",
            "aquatone": "https://github.com/michenriksen/aquatone",
            "puredns": "https://github.com/d3mondev/puredns"
        }
        
        missing_required = []
        missing_optional = []
        
        for tool, url in required_tools.items():
            if not shutil.which(tool):
                missing_required.append(f"{tool} ({url})")
        
        for tool, url in optional_tools.items():
            if not shutil.which(tool):
                missing_optional.append(f"{tool} ({url})")
        
        if missing_required:
            console.print("\n[bold red]Missing required tools:[/bold red]")
            for tool in missing_required:
                console.print(f"- {tool}")
            console.print("\nPlease install the missing required tools and try again.")
            sys.exit(1)
            
        if missing_optional:
            console.print("\n[bold yellow]Missing optional tools:[/bold yellow]")
            for tool in missing_optional:
                console.print(f"- {tool}")
            console.print("\nThe tool will work without these, but some functionality will be limited.")
            
    def create_dirs(self) -> None:
        """Create directory structure for outputs"""
        dirs = [
            self.output_dir,
            f"{self.output_dir}/subdomains",
            f"{self.output_dir}/screenshots",
            f"{self.output_dir}/endpoints",
            f"{self.output_dir}/js",
            f"{self.output_dir}/params",
            f"{self.output_dir}/vulns",
            f"{self.output_dir}/reports"
        ]
        
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
            
        console.print(f"[green]✓[/green] Created output directory structure at [bold]{self.output_dir}[/bold]")
        
    def run_command(self, command: str, silent: bool = False) -> subprocess.CompletedProcess:
        """Run a shell command with proper logging and error handling"""
        if not silent:
            self.logger.debug(f"Running command: {command}")
            
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                text=True, 
                capture_output=True
            )
            
            if result.returncode != 0 and not silent:
                self.logger.warning(f"Command returned non-zero exit code {result.returncode}: {command}")
                self.logger.debug(f"Error output: {result.stderr}")
            
            return result
        except Exception as e:
            self.logger.error(f"Error running command '{command}': {str(e)}")
            return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr=str(e))
        
    def passive_subdomain_enum(self) -> Set[str]:
        """Perform passive subdomain enumeration using multiple tools"""
        with console.status("[bold green]Starting passive subdomain enumeration...[/bold green]") as status:
            subdomain_dir = os.path.join(self.output_dir, "subdomains")
            all_subdomains = os.path.join(subdomain_dir, "all_passive.txt")
            
            # Run tools in parallel
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                tools = {
                    "subfinder": f"subfinder -d {self.target} -o {os.path.join(subdomain_dir, 'subfinder.txt')} -silent",
                    "assetfinder": f"assetfinder --subs-only {self.target} > {os.path.join(subdomain_dir, 'assetfinder.txt')}",
                    "amass": f"amass enum -passive -d {self.target} -o {os.path.join(subdomain_dir, 'amass.txt')}"
                }
                
                tasks = {}
                for tool, command in tools.items():
                    if shutil.which(tool.split()[0]):
                        task_id = progress.add_task(f"Running {tool}...", total=None)
                        tasks[tool] = task_id
                    else:
                        self.logger.warning(f"{tool} not found, skipping")
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(tools), self.threads)) as executor:
                    futures = {executor.submit(self.run_command, cmd): tool for tool, cmd in tools.items() if shutil.which(tool.split()[0])}
                    
                    for future in concurrent.futures.as_completed(futures):
                        tool = futures[future]
                        try:
                            result = future.result()
                            if result.returncode == 0:
                                progress.update(tasks[tool], description=f"[green]✓[/green] {tool} completed")
                            else:
                                progress.update(tasks[tool], description=f"[red]✗[/red] {tool} failed")
                        except Exception as e:
                            progress.update(tasks[tool], description=f"[red]✗[/red] {tool} error: {str(e)}")
            
            # Combine results
            self.run_command(f"cat {subdomain_dir}/*.txt 2>/dev/null | sort -u > {all_subdomains}")
            
            # Load subdomains
            try:
                with open(all_subdomains, 'r') as f:
                    self.results.subdomains = set(line.strip() for line in f if line.strip())
                console.print(f"[green]✓[/green] Found [bold]{len(self.results.subdomains)}[/bold] unique subdomains via passive enumeration")
            except FileNotFoundError:
                console.print("[yellow]![/yellow] No subdomains found in passive enumeration")
                
        return self.results.subdomains
    
    def active_subdomain_enum(self) -> Set[str]:
        """Perform active subdomain enumeration using brute force with n0kovo wordlist"""
        if not self.results.subdomains:
            self.passive_subdomain_enum()
            
        with console.status("[bold green]Starting active subdomain enumeration with n0kovo wordlist...[/bold green]"):
            subdomain_dir = os.path.join(self.output_dir, "subdomains")
            ffuf_output = os.path.join(subdomain_dir, "ffuf_brute.json")
            
            # Save existing subdomains to file for later combination
            passive_subdomains = os.path.join(subdomain_dir, "passive_subdomains.txt")
            with open(passive_subdomains, 'w') as f:
                for subdomain in sorted(self.results.subdomains):
                    f.write(f"{subdomain}\n")
            
            # Use puredns for DNS resolution if available
            if shutil.which("puredns"):
                console.print(f"[bold]Running puredns with {self.wordlists['subdomains']}...[/bold]")
                puredns_output = os.path.join(subdomain_dir, "puredns_brute.txt")
                cmd = f"puredns bruteforce {self.wordlists['subdomains']} {self.target} -r /etc/resolv.conf -w {puredns_output}"
                self.run_command(cmd)
                
                if os.path.exists(puredns_output):
                    with open(puredns_output, 'r') as f:
                        brute_domains = set(line.strip() for line in f if line.strip())
                    self.results.subdomains.update(brute_domains)
                    console.print(f"[green]✓[/green] Found [bold]{len(brute_domains)}[/bold] subdomains via puredns bruteforce")
            
            # FFUF as fallback or additional method
            else:
                console.print(f"[bold]Running ffuf with {self.wordlists['subdomains']}...[/bold]")
                cmd = f"ffuf -u http://FUZZ.{self.target} -w {self.wordlists['subdomains']} -o {ffuf_output} -of json -s"
                self.run_command(cmd)
                
                # Process ffuf results
                try:
                    with open(ffuf_output, 'r') as f:
                        ffuf_data = json.load(f)
                        for result in ffuf_data.get('results', []):
                            if 'input' in result and 'FUZZ' in result['input']:
                                subdomain = f"{result['input']['FUZZ']}.{self.target}"
                                self.results.subdomains.add(subdomain)
                except (FileNotFoundError, json.JSONDecodeError) as e:
                    self.logger.warning(f"Error processing ffuf results: {e}")
            
            # Update all subdomains file
            all_subdomains = os.path.join(subdomain_dir, "all_subdomains.txt")
            with open(all_subdomains, 'w') as f:
                for subdomain in sorted(self.results.subdomains):
                    f.write(f"{subdomain}\n")
                    
            console.print(f"[green]✓[/green] Total unique subdomains after brute forcing: [bold]{len(self.results.subdomains)}[/bold]")
            
        return self.results.subdomains
    
    def resolve_live_domains(self) -> Set[str]:
        """Resolve live domains using httpx"""
        if not self.results.subdomains:
            self.passive_subdomain_enum()
            
        with console.status("[bold green]Resolving live domains with httpx...[/bold green]"):
            subdomain_dir = os.path.join(self.output_dir, "subdomains")
            all_subdomains = os.path.join(subdomain_dir, "all_subdomains.txt")
            live_domains_file = os.path.join(subdomain_dir, "live_domains.txt")
            httpx_json = os.path.join(subdomain_dir, "httpx_results.json")
            
            # First ensure we have the combined subdomain list
            if not os.path.exists(all_subdomains):
                with open(all_subdomains, 'w') as f:
                    for subdomain in sorted(self.results.subdomains):
                        f.write(f"{subdomain}\n")
            
            # Run httpx with expanded capabilities
            cmd = (f"httpx -l {all_subdomains} -o {live_domains_file} -json {httpx_json} "
                   f"-status-code -title -tech-detect -favicon -follow-redirects -random-agent "
                   f"-timeout 10 -retries 2 -threads {self.threads}")
            self.run_command(cmd)
            
            # Load live domains
            try:
                with open(live_domains_file, 'r') as f:
                    self.results.live_domains = set(line.strip().split(' ')[0] for line in f if line.strip())
                
                # Load technology stack information
                if os.path.exists(httpx_json):
                    with open(httpx_json, 'r') as f:
                        for line in f:
                            try:
                                data = json.loads(line)
                                if 'technologies' in data and data['technologies']:
                                    self.results.tech_stack[data['url']] = data['technologies']
                            except json.JSONDecodeError:
                                continue
                
                console.print(f"[green]✓[/green] Found [bold]{len(self.results.live_domains)}[/bold] live domains")
            except FileNotFoundError:
                console.print("[yellow]![/yellow] No live domains found")
                
        return self.results.live_domains
    
    def take_screenshots(self) -> None:
        """Take screenshots of live domains"""
        if not self.results.live_domains:
            console.print("[yellow]![/yellow] No live domains to screenshot. Run resolve_live_domains first.")
            return
        
        with console.status("[bold green]Taking screenshots...[/bold green]"):
            live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
            screenshots_dir = os.path.join(self.output_dir, "screenshots")
            
            # Use aquatone or gowitness depending on availability
            if shutil.which("aquatone"):
                cmd = f"cat {live_domains_file} | aquatone -out {screenshots_dir}"
                self.run_command(cmd)
                console.print(f"[green]✓[/green] Screenshots saved to {screenshots_dir} with aquatone")
            elif shutil.which("gowitness"):
                cmd = f"gowitness file -f {live_domains_file} -P {screenshots_dir} --no-http"
                self.run_command(cmd)
                console.print(f"[green]✓[/green] Screenshots saved to {screenshots_dir} with gowitness")
            else:
                console.print("[yellow]![/yellow] Neither aquatone nor gowitness found for taking screenshots")
    
    def scan_for_takeovers(self) -> List[str]:
        """Scan for subdomain takeovers"""
        if not self.results.subdomains:
            console.print("[yellow]![/yellow] No subdomains found. Run passive_subdomain_enum first.")
            return []
        
        with console.status("[bold green]Scanning for subdomain takeovers...[/bold green]"):
            subdomain_dir = os.path.join(self.output_dir, "subdomains")
            all_subdomains = os.path.join(subdomain_dir, "all_subdomains.txt")
            takeover_tools = []
            
            # Check available tools and run them
            if shutil.which("nuclei"):
                takeover_file = os.path.join(subdomain_dir, "nuclei_takeovers.txt")
                cmd = f"nuclei -l {all_subdomains} -t takeovers/ -o {takeover_file} -silent"
                takeover_tools.append(("nuclei", takeover_file, cmd))
            
            if shutil.which("subzy"):
                takeover_file = os.path.join(subdomain_dir, "subzy_takeovers.txt")
                cmd = f"subzy run --targets {all_subdomains} --output {takeover_file}"
                takeover_tools.append(("subzy", takeover_file, cmd))
                
            if not takeover_tools:
                console.print("[yellow]![/yellow] No subdomain takeover tools found (nuclei/subzy)")
                return []
                
            # Run tools in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(takeover_tools)) as executor:
                futures = {executor.submit(self.run_command, cmd): (tool, output_file) for tool, output_file, cmd in takeover_tools}
                
                for future in concurrent.futures.as_completed(futures):
                    tool, output_file = futures[future]
                    try:
                        result = future.result()
                        console.print(f"[green]✓[/green] Completed {tool} scan")
                    except Exception as e:
                        console.print(f"[red]✗[/red] Error running {tool}: {str(e)}")
            
            # Combine results
            combined_takeovers = os.path.join(subdomain_dir, "takeovers.txt")
            takeover_files = " ".join(output_file for _, output_file, _ in takeover_tools)
            self.run_command(f"cat {takeover_files} 2>/dev/null | sort -u > {combined_takeovers}")
            
            # Load results
            try:
                with open(combined_takeovers, 'r') as f:
                    self.results.takeovers = [line.strip() for line in f if line.strip()]
                
                if self.results.takeovers:
                    console.print(f"[bold red]⚠[/bold red] Found [bold]{len(self.results.takeovers)}[/bold] potential subdomain takeovers!")
                else:
                    console.print("[green]✓[/green] No subdomain takeovers found")
            except FileNotFoundError:
                console.print("[green]✓[/green] No subdomain takeovers found")
                
        return self.results.takeovers
    
    def crawl_endpoints(self) -> Set[str]:
        """Crawl endpoints using modern tools"""
        if not self.results.live_domains:
            console.print("[yellow]![/yellow] No live domains for crawling. Run resolve_live_domains first.")
            return set()
        
        with console.status("[bold green]Crawling endpoints...[/bold green]"):
            live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
            urls_file = os.path.join(self.output_dir, "endpoints", "urls.txt")
            js_files = os.path.join(self.output_dir, "js", "js_files.txt")
            
            # Use katana if available
            if shutil.which("katana"):
                console.print("[bold]Running katana for URL discovery...[/bold]")
                cmd = f"katana -list {live_domains_file} -jc -o {urls_file} -threads {self.threads}"
                self.run_command(cmd)
            # Use gospider as fallback
            elif shutil.which("gospider"):
                console.print("[bold]Running gospider for URL discovery...[/bold]")
                cmd = f"gospider -S {live_domains_file} -o {self.output_dir}/endpoints/gospider -c {self.threads} -d 3"
                self.run_command(cmd)
                # Combine gospider results
                self.run_command(f"find {self.output_dir}/endpoints/gospider -type f -exec cat {{}} \\; | grep -Eo '(http|https)://[^[:space:]]+' | sort -u > {urls_file}")
            else:
                console.print("[yellow]![/yellow] No web crawling tools found (katana/gospider)")
                return set()
            
            # Extract JS files
            self.run_command(f"cat {urls_file} 2>/dev/null | grep -i '\\.js$' | sort -u > {js_files}")
            
            # Process JS files for endpoint discovery
            endpoints_file = os.path.join(self.output_dir, "endpoints", "js_endpoints.txt")
            
            # Use different JS analysis tools based on availability
            if shutil.which("gau"):
                console.print("[bold]Running gau for additional URL discovery...[/bold]")
                gau_file = os.path.join(self.output_dir, "endpoints", "gau_urls.txt")
                with open(live_domains_file, 'r') as f:
                    domains = [line.strip().split(' ')[0] for line in f if line.strip()]
                    # Take at most 10 domains to avoid excessive time
                    sample_domains = domains[:10] if len(domains) > 10 else domains
                
                for domain in sample_domains:
                    domain = domain.replace("http://", "").replace("https://", "").split('/')[0]
                    cmd = f"gau --threads {self.threads} {domain} >> {gau_file}"
                    self.run_command(cmd)
                
                # Combine with other URLs
                self.run_command(f"cat {gau_file} {urls_file} 2>/dev/null | sort -u > {urls_file}.tmp && mv {urls_file}.tmp {urls_file}")
            
            # Extract endpoints from JS files
            if os.path.exists(js_files) and os.path.getsize(js_files) > 0:
                if shutil.which("LinkFinder") or os.path.exists("/path/to/LinkFinder/linkfinder.py"):
                    linkfinder_path = shutil.which("LinkFinder") or "/path/to/LinkFinder/linkfinder.py"
                    console.print("[bold]Extracting endpoints from JS files with LinkFinder...[/bold]")
                    cmd = f"cat {js_files} | while read url; do python3 {linkfinder_path} -i \"$url\" -o cli >> {endpoints_file}; done"
                    self.run_command(cmd)
            
            # Load results
            try:
                with open(urls_file, 'r') as f:
                    self.results.urls = set(line.strip() for line in f if line.strip())
                
                if os.path.exists(js_files):
                    with open(js_files, 'r') as f:
                        self.results.js_files = set(line.strip() for line in f if line.strip())
                        
                if os.path.exists(endpoints_file):        
                    with open(endpoints_file, 'r') as f:
                        self.results.endpoints = set(line.strip() for line in f if line.strip())
                        
                console.print(f"[green]✓[/green] Discovered [bold]{len(self.results.urls)}[/bold] URLs and [bold]{len(self.results.js_files)}[/bold] JavaScript files")
                
                if self.results.endpoints:
                    console.print(f"[green]✓[/green] Extracted [bold]{len(self.results.endpoints)}[/bold] endpoints from JavaScript")
            except FileNotFoundError:
                console.print("[yellow]![/yellow] Issue loading crawled endpoints")
                
        return self.results.urls
    
    def directory_bruteforce(self) -> None:
        """Brute force directories using ffuf or dirsearch"""
        if not self.results.live_domains:
            console.print("[yellow]![/yellow] No live domains for directory brute forcing. Run resolve_live_domains first.")
            return
        
        # Using a smaller list of domains for dir bruteforcing to avoid excessive time
        sample_domains = list(self.results.live_domains)[:5] if len(self.results.live_domains) > 5 else list(self.results.live_domains)
        
        with console.status(f"[bold green]Brute forcing directories for {len(sample_domains)} domains...[/bold green]"):
            # Use ffuf or dirsearch based on availability
            if shutil.which("ffuf"):
                for domain in sample_domains:
                    output_file = os.path.join(
                        self.output_dir, 
                        "endpoints", 
                        f"{domain.replace('://', '_').replace('.', '_').replace('/', '_')}_dirs.json"
                    )
                    self.logger.info(f"Brute forcing directories for {domain}...")
                    
                    cmd = f"ffuf -u {domain}/FUZZ -w {self.wordlists['directories']} -mc 200,204,301,302,307,401,403 -o {output_file} -of json -s"
                    self.run_command(cmd)
            elif shutil.which("dirsearch"):
                for domain in sample_domains:
                    output_file = os.path.join(
                        self.output_dir, 
                        "endpoints", 
                        f"{domain.replace('://', '_').replace('.', '_').replace('/', '_')}_dirs.txt"
                    )
                    self.logger.info(f"Brute forcing directories for {domain}...")
                    
                    cmd = f"dirsearch -u {domain} -w {self.wordlists['directories']} -o {output_file} --format=plain -q"
                    self.run_command(cmd)
            else:
                console.print("[yellow]![/yellow] No directory brute force tools found (ffuf/dirsearch)")
                return
                
            console.print("[green]✓[/green] Directory brute forcing completed")
    
    def find_parameters(self) -> Set[str]:
        """Find parameters using various tools"""
        endpoints_file = os.path.join(self.output_dir, "endpoints", "urls.txt")
        if
