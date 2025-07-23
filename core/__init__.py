"""
C2 Hunter Core Module

This package contains the core functionality for C2 Hunter including:
- VirusTotal API fetcher
- Domain analysis
- Threat visualization
- Report generation
"""

from .fetcher import VirusTotalFetcher
from .analyzer import DomainAnalyzer
from .visualizer import ThreatVisualizer
from .reporter import ReportGenerator

__all__ = ['VirusTotalFetcher', 'DomainAnalyzer', 'ThreatVisualizer', 'ReportGenerator']
__version__ = '1.0.0'