import argparse
import os
import json
from datetime import datetime
from core.fetcher import VirusTotalFetcher
from core.fetcher import VirusTotalFetcher
from core.analyzer import DomainAnalyzer
from core.visualizer import ThreatVisualizer
from core.reporter import ReportGenerator
from config import Config

def run(ip, output_dir=None):
    output_dir = output_dir or Config.OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Starting analysis for IP: {ip}")
    print("[*] This may take several minutes depending on the number of domains...")
    
    fetcher = VirusTotalFetcher()
    
    print("[*] Fetching related domains...")
    domains = fetcher.get_related_domains(ip)
    
    if not domains:
        print("[!] No domains found for this IP address")
        return
        
    print(f"[+] Found {len(domains)} domains. Analyzing...")
    
    domain_data_list = []
    
    for i, domain in enumerate(domains, 1):
        print(f"[*] Analyzing domain {i}/{len(domains)}: {domain}")
        
        info = fetcher.get_domain_info(domain)
        if not info:
            continue
            
        c2_flag = DomainAnalyzer.is_c2_domain(info)
        risk_info = DomainAnalyzer.get_domain_risk(info)
        
        domain_data_list.append((
            domain,
            {
                "c2": c2_flag,
                **risk_info
            }
        ))
    
    print("[+] Analysis complete!")
    
    json_report = ReportGenerator.generate_json_report(ip, domain_data_list, output_dir)
    md_report = ReportGenerator.generate_markdown_report(ip, domain_data_list, output_dir)
    graph_file = os.path.join(output_dir, f"c2_graph_{ip}.html")
    
    # Visualize
    ThreatVisualizer.create_graph(ip, domain_data_list, graph_file)
    
    print("\n[+] Results:")
    print(f"  - JSON report: {json_report}")
    print(f"  - Markdown report: {md_report}")
    print(f"  - Interactive graph: {graph_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C2Hunter - Command & Control Detection Tool")
    parser.add_argument("--ip", "-p", required=True, help="Target IP address to analyze")
    parser.add_argument("--output", help="Output directory for reports")
    args = parser.parse_args()

    run(args.ip, args.output)