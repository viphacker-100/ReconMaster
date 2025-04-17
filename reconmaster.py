#!/usr/bin/env python3
import os
import argparse
import subprocess
import concurrent.futures
import json
import time
import sys
import logging
import shutil
import requests
import yaml
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ReconMaster:
    def __init__(self, target, output_dir, threads=10, wordlist=None, config_file=None, 
                 verbose=False, resume=False):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = output_dir
        self.output_dir = os.path.join(output_dir, f"{target}_{self.timestamp}")
        self.threads = threads
        self.verbose = verbose
        self.resume = resume
        self.subdomains = set()
        self.live_domains = set()
        self.urls = set()
        self.js_files = set()
        self.endpoints = set()
        self.parameters = set()
        self.tech_stack = {}
        self.takeovers = []
        self.broken_links = []
        self.vulnerabilities = []
        self.progress = {}
        self.config = self.load_config(config_file)
        
        # Set up logging
        self.setup_logging()
        
        # Default wordlist if none specified
        self.wordlist = wordlist if wordlist else self.config.get('wordlists', {}).get(
            'subdomains', "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt")
        
        # Create output directory structure
        self.create_dirs()
        
        # Load progress file if resuming
        if self.resume:
            self.load_progress()
    
    def setup_logging(self):
        """Set up logging configuration"""
        log_file = os.path.join(self.base_dir, f"{self.target}_reconmaster.log")
        log_level = logging.DEBUG if self.verbose else logging.INFO
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("ReconMaster")
        self.logger.info(f"Starting ReconMaster for {self.target}")
    
    def load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'tools': {
                'subfinder': 'subfinder',
                'assetfinder': 'assetfinder',
                'amass': 'amass',
                'ffuf': 'ffuf',
                'httpx': 'httpx',
                'gowitness': 'gowitness',
                'subzy': 'subzy',
                'katana': 'katana',
                'arjun': 'arjun',
                'nmap': 'nmap',
                'nuclei': 'nuclei',
                'linkfinder': '/usr/local/bin/linkfinder.py',
                'waybackurls': 'waybackurls',
                'gau': 'gau',
                'socialhunter': 'socialhunter'
            },
            'wordlists': {
                'subdomains': '/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt',
                'content': '/usr/share/seclists/Discovery/Web-Content/common.txt',
                'parameters': '/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt'
            },
            'api_keys': {
                'shodan': '',
                'censys': '',
                'securitytrails': '',
                'virustotal': ''
            },
            'settings': {
                'screenshot_timeout': 30,
                'max_depth_crawl': 2,
                'sample_size': 20,
                'nuclei_severity': 'critical,high,medium',
                'subdomain_permutations': True,
                'use_proxy': False,
                'proxy': 'http://127.0.0.1:8080'
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                
                # Deep merge user config with default config
                for category in user_config:
                    if category in default_config and isinstance(default_config[category], dict):
                        default_config[category].update(user_config[category])
                    else:
                        default_config[category] = user_config[category]
                        
                return default_config
            except Exception as e:
                print(f"Error loading config file: {e}")
                return default_config
        else:
            return default_config
        
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
            f"{self.output_dir}/ports",
            f"{self.output_dir}/tech",
            f"{self.output_dir}/archives"
        ]
        
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
            
        self.logger.info(f"Created output directory structure at {self.output_dir}")
    
    def save_progress(self):
        """Save current progress to file"""
        progress_file = os.path.join(self.output_dir, "progress.json")
        
        self.progress = {
            "target": self.target,
            "timestamp": self.timestamp,
            "modules_completed": self.progress,
            "subdomains_count": len(self.subdomains),
            "live_domains_count": len(self.live_domains),
            "urls_count": len(self.urls),
            "js_files_count": len(self.js_files)
        }
        
        with open(progress_file, 'w') as f:
            json.dump(self.progress, f)
        
        self.logger.debug(f"Progress saved to {progress_file}")
    
    def load_progress(self):
        """Load progress from file if resuming a scan"""
        # Find the most recent scan directory for this target
        target_dirs = [d for d in os.listdir(self.base_dir) 
                      if os.path.isdir(os.path.join(self.base_dir, d)) and d.startswith(f"{self.target}_")]
        
        if not target_dirs:
            self.logger.warning("No previous scan found to resume")
            return
        
        # Sort by timestamp (directory name)
        latest_dir = sorted(target_dirs)[-1]
        progress_file = os.path.join(self.base_dir, latest_dir, "progress.json")
        
        if os.path.exists(progress_file):
            try:
                with open(progress_file, 'r') as f:
                    self.progress = json.load(f)
                
                # Update output directory to the previous scan directory
                self.output_dir = os.path.join(self.base_dir, latest_dir)
                self.timestamp = latest_dir.split('_')[-1]
                
                # Load saved data
                self.load_saved_data()
                
                self.logger.info(f"Resuming scan from {self.output_dir}")
            except Exception as e:
                self.logger.error(f"Error loading progress file: {e}")
        else:
            self.logger.warning("No progress file found to resume")
    
    def load_saved_data(self):
        """Load saved data from files when resuming a scan"""
        # Load subdomains
        subdomains_file = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        if os.path.exists(subdomains_file):
            with open(subdomains_file, 'r') as f:
                self.subdomains = set([line.strip() for line in f if line.strip()])
        
        # Load live domains
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        if os.path.exists(live_domains_file):
            with open(live_domains_file, 'r') as f:
                self.live_domains = set([line.strip().split(' ')[0] for line in f if line.strip()])
        
        # Load URLs
        urls_file = os.path.join(self.output_dir, "endpoints", "urls.txt")
        if os.path.exists(urls_file):
            with open(urls_file, 'r') as f:
                self.urls = set([line.strip() for line in f if line.strip()])
        
        # Load JS files
        js_files = os.path.join(self.output_dir, "js", "js_files.txt")
        if os.path.exists(js_files):
            with open(js_files, 'r') as f:
                self.js_files = set([line.strip() for line in f if line.strip()])
    
    def run_command(self, command, silent=False):
        """Run a shell command with proper error handling"""
        if self.verbose and not silent:
            self.logger.debug(f"Running command: {command}")
        
        try:
            if silent:
                result = subprocess.run(
                    command, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:
                result = subprocess.run(command, shell=True)
            
            if result.returncode != 0:
                if silent:
                    self.logger.error(f"Command failed: {command}")
                    self.logger.error(f"Error: {result.stderr}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Exception running command: {e}")
            return False
    
    def check_tools(self):
        """Check if required tools are installed"""
        self.logger.info("Checking required tools")
        missing_tools = []
        
        for tool, path in self.config['tools'].items():
            if not shutil.which(path) and not os.path.isfile(path):
                missing_tools.append(tool)
        
        if missing_tools:
            self.logger.warning(f"Missing tools: {', '.join(missing_tools)}")
            self.logger.warning("Some functionality may be limited")
        else:
            self.logger.info("All required tools are installed")
            
        return len(missing_tools) == 0
    
    def passive_subdomain_enum(self):
        """Perform passive subdomain enumeration"""
        if self.progress.get('passive_subdomain_enum', False) and self.resume:
            self.logger.info("Skipping passive subdomain enumeration (already completed)")
            return self.subdomains
        
        self.logger.info(f"Starting passive subdomain enumeration for {self.target}")
        
        # Subfinder
        subfinder = self.config['tools']['subfinder']
        subfinder_output = os.path.join(self.output_dir, "subdomains", "subfinder.txt")
        self.logger.info("Running subfinder...")
        
        subfinder_cmd = f"{subfinder} -d {self.target} -o {subfinder_output}"
        if self.config['api_keys'].get('securitytrails'):
            subfinder_cmd += f" -provider securitytrails -securitytrails-key {self.config['api_keys']['securitytrails']}"
        if self.config['api_keys'].get('virustotal'):
            subfinder_cmd += f" -provider virustotal -virustotal-key {self.config['api_keys']['virustotal']}"
        
        self.run_command(subfinder_cmd)
        
        # Assetfinder
        assetfinder = self.config['tools']['assetfinder']
        assetfinder_output = os.path.join(self.output_dir, "subdomains", "assetfinder.txt")
        self.logger.info("Running assetfinder...")
        self.run_command(f"{assetfinder} --subs-only {self.target} > {assetfinder_output}")
        
        # Amass passive
        amass = self.config['tools']['amass']
        amass_output = os.path.join(self.output_dir, "subdomains", "amass.txt")
        self.logger.info("Running amass passive...")
        self.run_command(f"{amass} enum -passive -d {self.target} -o {amass_output}")
        
        # Waybackurls for historical subdomains
        waybackurls = self.config['tools']['waybackurls']
        wayback_output = os.path.join(self.output_dir, "archives", "wayback.txt")
        self.logger.info("Fetching URLs from Wayback Machine...")
        self.run_command(f"echo {self.target} | {waybackurls} > {wayback_output}")
        
        # GAU for more URL discovery
        gau = self.config['tools']['gau']
        gau_output = os.path.join(self.output_dir, "archives", "gau.txt")
        self.logger.info("Fetching URLs with GAU...")
        self.run_command(f"{gau} {self.target} --threads {self.threads} > {gau_output}")
        
        # Extract subdomains from wayback and gau results
        wayback_domains_output = os.path.join(self.output_dir, "subdomains", "wayback_domains.txt")
        self.run_command(f"cat {wayback_output} {gau_output} | grep -Po '(https?://)?\w+\.{self.target.replace('.','\.')}' | sort -u | sed 's/https\\?:\\/\\///' > {wayback_domains_output}")
        
        # Combine results
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_passive.txt")
        self.run_command(f"cat {self.output_dir}/subdomains/*.txt | sort -u > {all_subdomains}")
        
        # Load subdomains
        try:
            with open(all_subdomains, 'r') as f:
                self.subdomains = set([line.strip() for line in f if line.strip()])
            self.logger.info(f"Found {len(self.subdomains)} unique subdomains via passive enumeration")
        except FileNotFoundError:
            self.logger.warning("No subdomains found in passive enumeration")
        
        # Mark this step as completed
        self.progress['passive_subdomain_enum'] = True
        self.save_progress()
        
        return self.subdomains
    
    def active_subdomain_enum(self):
        """Perform active subdomain enumeration using brute force"""
        if self.progress.get('active_subdomain_enum', False) and self.resume:
            self.logger.info("Skipping active subdomain enumeration (already completed)")
            return self.subdomains
        
        self.logger.info(f"Starting active subdomain enumeration for {self.target}")
        
        # Use ffuf for brute forcing subdomains
        ffuf = self.config['tools']['ffuf']
        ffuf_output = os.path.join(self.output_dir, "subdomains", "ffuf_brute.json")
        self.logger.info(f"Running ffuf with wordlist {self.wordlist}...")
        
        cmd = f"{ffuf} -u http://FUZZ.{self.target} -w {self.wordlist} -o {ffuf_output} -of json -s"
        self.run_command(cmd)
        
        # Process ffuf results
        try:
            with open(ffuf_output, 'r') as f:
                ffuf_data = json.load(f)
                for result in ffuf_data.get('results', []):
                    if 'input' in result and 'FUZZ' in result['input']:
                        subdomain = f"{result['input']['FUZZ']}.{self.target}"
                        self.subdomains.add(subdomain)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Error processing ffuf results: {e}")
        
        # DNS permutation if enabled
        if self.config['settings'].get('subdomain_permutations', True):
            self.logger.info("Performing DNS permutation...")
            # Use dnsgen or similar tool if available
            if shutil.which('dnsgen'):
                permutation_list = os.path.join(self.output_dir, "subdomains", "permutations.txt")
                permutation_output = os.path.join(self.output_dir, "subdomains", "resolved_permutations.txt")
                
                with open(os.path.join(self.output_dir, "subdomains", "all_passive.txt"), 'r') as f:
                    seed_domains = f.read()
                
                # Generate permutations
                self.run_command(f"cat {os.path.join(self.output_dir, 'subdomains', 'all_passive.txt')} | dnsgen - > {permutation_list}")
                
                # Resolve permutations
                self.run_command(f"massdns -r /usr/share/wordlists/resolvers.txt -t A -o S -w {permutation_output} {permutation_list}")
                
                # Extract valid subdomains
                valid_permutations = os.path.join(self.output_dir, "subdomains", "valid_permutations.txt")
                self.run_command(f"cat {permutation_output} | grep -v NXDOMAIN | cut -d' ' -f1 > {valid_permutations}")
                
                # Add to subdomains
                try:
                    with open(valid_permutations, 'r') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain.endswith('.'):
                                subdomain = subdomain[:-1]  # Remove trailing dot
                            self.subdomains.add(subdomain)
                except FileNotFoundError:
                    self.logger.warning("No valid permutations found")
        
        # Update all subdomains file
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        with open(all_subdomains, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
                
        self.logger.info(f"Total unique subdomains after brute forcing: {len(self.subdomains)}")
        
        # Mark this step as completed
        self.progress['active_subdomain_enum'] = True
        self.save_progress()
        
        return self.subdomains
    
    def resolve_live_domains(self):
        """Resolve live domains using httpx"""
        if self.progress.get('resolve_live_domains', False) and self.resume:
            self.logger.info("Skipping live domain resolution (already completed)")
            return self.live_domains
        
        self.logger.info("Resolving live domains with httpx")
        
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        tech_file = os.path.join(self.output_dir, "tech", "technologies.json")
        
        # First ensure we have the combined subdomain list
        if not os.path.exists(all_subdomains):
            with open(all_subdomains, 'w') as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
        
        # Run httpx with enhanced options
        httpx = self.config['tools']['httpx']
        cmd = f"{httpx} -l {all_subdomains} -o {live_domains_file} -json -tech-detect -title -status-code -content-length -web-server -ip -cdn -cname -asn -follow-redirects -response-time -no-color"
        if self.config['settings'].get('use_proxy', False):
            cmd += f" -proxy {self.config['settings']['proxy']}"
        
        self.run_command(cmd)
        
        # Process JSON output for tech stack information
        httpx_json = os.path.join(self.output_dir, "subdomains", "httpx_results.json")
        cmd = f"{httpx} -l {all_subdomains} -json -o {httpx_json} -tech-detect -title -status-code -content-length -web-server -ip -cdn -cname -asn -follow-redirects -response-time -silent"
        self.run_command(cmd)
        
        # Extract technology information
        try:
            with open(httpx_json, 'r') as f:
                lines = f.readlines()
                tech_data = {}
                
                for line in lines:
                    try:
                        result = json.loads(line)
                        url = result.get('url', '')
                        tech_result = {
                            'url': url,
                            'status_code': result.get('status_code', ''),
                            'title': result.get('title', ''),
                            'webserver': result.get('webserver', ''),
                            'content_length': result.get('content_length', ''),
                            'technologies': result.get('technologies', []),
                            'ip': result.get('host', ''),
                            'cdn': result.get('cdn', False),
                            'cname': result.get('cname', []),
                            'asn': result.get('asn', '')
                        }
                        tech_data[url] = tech_result
                    except json.JSONDecodeError:
                        continue
                
                # Save technology information
                with open(tech_file, 'w') as tf:
                    json.dump(tech_data, tf, indent=4)
                
                self.logger.info(f"Technology information saved to {tech_file}")
        except Exception as e:
            self.logger.error(f"Error processing technology information: {e}")
        
        # Load live domains
        try:
            with open(live_domains_file, 'r') as f:
                for line in f:
                    if line.strip():
                        domain = line.strip().split(' ')[0]
                        self.live_domains.add(domain)
            self.logger.info(f"Found {len(self.live_domains)} live domains")
        except FileNotFoundError:
            self.logger.warning("No live domains found")
        
        # Mark this step as completed
        self.progress['resolve_live_domains'] = True
        self.save_progress()
        
        return self.live_domains
    
    def take_screenshots(self):
        """Take screenshots of live domains using gowitness"""
        if self.progress.get('take_screenshots', False) and self.resume:
            self.logger.info("Skipping screenshots (already completed)")
            return
        
        self.logger.info("Taking screenshots with gowitness")
        
        if not self.live_domains:
            self.logger.warning("No live domains to screenshot. Run resolve_live_domains first.")
            return
        
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        screenshots_dir = os.path.join(self.output_dir, "screenshots")
        
        # Run gowitness with improved settings
        gowitness = self.config['tools']['gowitness']
        timeout = self.config['settings'].get('screenshot_timeout', 30)
        
        cmd = f"{gowitness} file -f {live_domains_file} -P {screenshots_dir} --no-http --timeout {timeout} --chrome-timeout {timeout}"
        self.run_command(cmd)
        
        # Generate report
        report_path = os.path.join(screenshots_dir, "report.html")
        self.run_command(f"{gowitness} report generate -o {report_path}")
        
        self.logger.info(f"Screenshots saved to {screenshots_dir}")
        self.logger.info(f"Screenshot report available at {report_path}")
        
        # Mark this step as completed
        self.progress['take_screenshots'] = True
        self.save_progress()
    
    def scan_for_takeovers(self):
        """Scan for subdomain takeovers using subzy"""
        if self.progress.get('scan_for_takeovers', False) and self.resume:
            self.logger.info("Skipping subdomain takeover scanning (already completed)")
            return
        
        self.logger.info("Scanning for subdomain takeovers with subzy")
        
        all_subdomains = os.path.join(self.output_dir, "subdomains", "all_subdomains.txt")
        takeovers_file = os.path.join(self.output_dir, "subdomains", "takeovers.txt")
        
        # Run subzy with improved settings
        subzy = self.config['tools']['subzy']
        cmd = f"{subzy} run --targets {all_subdomains} --output {takeovers_file} --concurrency {self.threads} --verify"
        self.run_command(cmd)
        
        # Check results
        try:
            with open(takeovers_file, 'r') as f:
                self.takeovers = [line.strip() for line in f if line.strip()]
            if self.takeovers:
                self.logger.info(f"Found {len(self.takeovers)} potential subdomain takeovers!")
            else:
                self.logger.info("No subdomain takeovers found")
        except FileNotFoundError:
            self.logger.info("No subdomain takeovers found")
        
        # Mark this step as completed
        self.progress['scan_for_takeovers'] = True
        self.save_progress()
    
    def crawl_endpoints(self):
        """Crawl endpoints using katana and other tools"""
        if self.progress.get('crawl_endpoints', False) and self.resume:
            self.logger.info("Skipping endpoint crawling (already completed)")
            return
        
        self.logger.info("Crawling endpoints with katana")
        
        if not self.live_domains:
            self.logger.warning("No live domains for crawling. Run resolve_live_domains first.")
            return
        
        live_domains_file = os.path.join(self.output_dir, "subdomains", "live_domains.txt")
        urls_file = os.path.join(self.output_dir, "endpoints", "urls.txt")
        js_files = os.path.join(self.output_dir, "js", "js_files.txt")
        
        # Run katana to discover URLs with improved settings
        katana = self.config['tools']['katana']
        max_depth = self.config['settings'].get('max_depth_crawl', 2)
        
        self.logger.info("Running katana for URL discovery...")
        cmd = f"{katana} -list {live_domains_file} -jc -o {urls_file} -d {max_depth} -concurrency {self.threads*2} -timeout 20 -rate-limit 10"
        self.run_command(cmd)
        
        # Extract JS files
        self.logger.info("Extracting JavaScript files...")
        self.run_command(f"cat {urls_file} | grep '\\.js$' | grep -v '\\?\\|#' > {js_files}")
        
        # Run LinkFinder on JS files for endpoint discovery
        linkfinder = self.config['tools']['linkfinder']
        if os.path.exists(linkfinder):
            self.logger.info("Running LinkFinder on JS files...")
            endpoints_file = os.path.join(self.output_dir, "endpoints", "js_endpoints.txt")
            
            # Process JS files in batches to avoid command line length issues
            with open(js_files, 'r') as f:
                js_list = [line.strip() for line in f if line.strip()]
            
            if js_list:
                # Process in batches of 20
                batch_size = 20
                total_batches = (len(js_list) + batch_size - 1) // batch_size
                
                for i in range(0, len(js_list), batch_size):
                    batch = js_list[i:i+batch_size]
                    batch_file = os.path.join(self.output_dir, "js", f"batch_{i//batch_size}.txt")
                    
                    with open(batch_file, 'w') as bf:
                        for js_url in batch:
                            bf.write(f"{js_url}\n")
                    
                    self.logger.info(f"Processing batch {(i//batch_size)+1}/{total_batches} of JS files...")
                    cmd = f"cat {batch_file} | parallel -j{self.threads} 'python3 {linkfinder} -i {{}} -o cli >> {endpoints_file} 2>/dev/null'"
                    self.run_command(cmd)
            else:
                self.logger.info("No JavaScript files found to analyze")
        else:
            self.logger.warning(f"LinkFinder not found at {linkfinder}. Skipping JS endpoint discovery.")
        
        # Process Wayback and GAU data for endpoints
        wayback_output = os.path.join(self.output_dir, "archives", "wayback.txt")
        gau_output = os.path.join(self.output_dir, "archives", "gau.txt")
        archive_endpoints = os.path.join(self.output_dir, "endpoints", "archive_endpoints.txt")
        
        if os.path.exists(wayback_output) and os.path.exists(gau_output):
            self.logger.info("Processing archive data for endpoints...")
            cmd = f"cat {wayback_output} {gau_output} | sort -u > {archive_endpoints}"
            self.run_command(cmd)
        
        # Combine
