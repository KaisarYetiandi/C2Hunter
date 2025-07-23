import json
import os
from datetime import datetime
from config import Config
from typing import List, Dict, Tuple

class ReportGenerator:
    @staticmethod
    def generate_json_report(ip: str, domain_data_list: List[Tuple[str, Dict]], output_dir: str = None) -> str:
        output_dir = output_dir or Config.OUTPUT_DIR
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(output_dir, f"c2_report_{ip}_{timestamp}.json")
        
        report = {
            "metadata": {
                "ip": ip,
                "generated_at": datetime.now().isoformat(),
                "total_domains": len(domain_data_list),
                "c2_domains": sum(1 for _, data in domain_data_list if data.get("c2", False))
            },
            "domains": [
                {
                    "domain": domain,
                    **data
                } for domain, data in domain_data_list
            ]
        }
        
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
            
        return filename
        
    @staticmethod
    def generate_markdown_report(ip: str, domain_data_list: List[Tuple[str, Dict]], output_dir: str = None) -> str:
        output_dir = output_dir or Config.OUTPUT_DIR
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(output_dir, f"c2_report_{ip}_{timestamp}.md")
        
        c2_count = sum(1 for _, data in domain_data_list if data.get("c2", False))
        
        with open(filename, "w") as f:
            f.write(f"# C2 Hunter Report\n\n")
            f.write(f"- **Target IP**: `{ip}`\n")
            f.write(f"- **Report Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **Total Domains Analyzed**: {len(domain_data_list)}\n")
            f.write(f"- **Potential C2 Domains**: {c2_count}\n\n")
            
            f.write("## Domain Analysis\n\n")
            f.write("| Domain | Risk Level | Score | Malicious | Suspicious | C2 Detected |\n")
            f.write("|--------|------------|-------|-----------|------------|-------------|\n")
            
            for domain, data in sorted(domain_data_list, key=lambda x: x[1].get("score", 0), reverse=True):
                f.write(
                    f"| {domain} | {data.get('risk', 'unknown').upper()} | {data.get('score', 0)} | "
                    f"{data.get('malicious', 0)} | {data.get('suspicious', 0)} | "
                    f"{'✅' if data.get('c2', False) else '❌'} |\n"
                )
                
        return filename