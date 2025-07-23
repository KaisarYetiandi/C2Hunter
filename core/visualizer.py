from pyvis.network import Network
import os
from typing import List, Tuple, Dict
from config import Config
import webbrowser

class ThreatVisualizer:
    @staticmethod
    def create_graph(ip: str, domain_data_list: List[Tuple[str, Dict]], output_file: str) -> str:
        net = Network(
            height="900px",
            width="100%",
            bgcolor="#1e1e2d",
            font_color="#ffffff",
            directed=True,
            notebook=False
        )
        
        net.set_options("""
        {
            "physics": {
                "barnesHut": {
                    "gravitationalConstant": -80000,
                    "centralGravity": 0.3,
                    "springLength": 200,
                    "springConstant": 0.04,
                    "damping": 0.09,
                    "avoidOverlap": 0.1
                },
                "maxVelocity": 50,
                "minVelocity": 0.1
            }
        }
        """)
        
        net.add_node(
            ip,
            label=f"IP: {ip}",
            color="#ff4757",
            shape="dot",
            size=25,
            title=f"Source IP: {ip}",
            physics=True
        )
        
        for domain, info in domain_data_list:
            risk = info.get("risk", "unknown")
            colors = {
                "critical": "#ff4757",
                "high": "#ff6b81",
                "medium": "#ffa502",
                "low": "#eccc68",
                "clean": "#2ed573",
                "unknown": "#a4b0be"
            }
            
            title = (
                f"<b>Domain:</b> {domain}<br>"
                f"<b>Risk:</b> {risk.upper()}<br>"
                f"<b>Score:</b> {info.get('score', 0)}<br>"
                f"<b>Malicious:</b> {info.get('malicious', 0)}<br>"
                f"<b>Suspicious:</b> {info.get('suspicious', 0)}<br>"
                f"<b>C2 Detection:</b> {'Yes' if info.get('c2', False) else 'No'}"
            )
            
            net.add_node(
                domain,
                label=domain,
                color=colors.get(risk, "#a4b0be"),
                title=title,
                shape="box",
                size=15 + min(info.get('score', 0), 20),
                physics=True
            )
            
            net.add_edge(
                ip,
                domain,
                color="#5352ed",
                width=1 + min(info.get('score', 0)/5, 3),
                title=f"Connections from {ip}"
            )
        
        os.makedirs(os.path.dirname(output_file) or Config.OUTPUT_DIR, exist_ok=True)
        net.show(output_file)
        return output_file