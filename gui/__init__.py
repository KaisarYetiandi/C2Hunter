"""
C2 Hunter GUI Package

This package contains all GUI components for the C2 Hunter application.
"""

from .main_window import C2HunterGUI
from .dialogs import SettingsDialog, AboutDialog
from .resources import initialize_resources

__all__ = ['C2HunterGUI', 'SettingsDialog', 'AboutDialog', 'initialize_resources']
__version__ = '1.0.0'