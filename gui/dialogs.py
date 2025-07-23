from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QLineEdit, QDialogButtonBox,
    QFormLayout, QTabWidget, QTextBrowser
)
from PyQt5.QtCore import Qt
from qt_material import apply_stylesheet

class SettingsDialog(QDialog):
    """Application settings dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)
        
        self.init_ui()
        apply_stylesheet(self, theme='dark_teal.xml')
        
    def init_ui(self):
        layout = QVBoxLayout()
      
        tabs = QTabWidget()
      
        api_tab = QWidget()
        api_layout = QFormLayout(api_tab)
        
        self.vt_api_input = QLineEdit()
        api_layout.addRow("VirusTotal API Key:", self.vt_api_input)
        
        self.output_dir_input = QLineEdit()
        api_layout.addRow("Output Directory:", self.output_dir_input)
        
        tabs.addTab(api_tab, "API Settings")
     
        app_tab = QWidget()
        app_layout = QFormLayout(app_tab)
        
        self.max_domains_input = QLineEdit()
        app_layout.addRow("Max Domains to Analyze:", self.max_domains_input)
        
        tabs.addTab(app_tab, "Application")
        
        layout.addWidget(tabs)
     
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            Qt.Horizontal, self
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def get_settings(self):
        """Return current settings from dialog"""
        return {
            'vt_api_key': self.vt_api_input.text(),
            'output_dir': self.output_dir_input.text(),
            'max_domains': self.max_domains_input.text()
        }
    
    def set_settings(self, settings):
        """Populate dialog with settings"""
        self.vt_api_input.setText(settings.get('vt_api_key', ''))
        self.output_dir_input.setText(settings.get('output_dir', ''))
        self.max_domains_input.setText(settings.get('max_domains', ''))

class AboutDialog(QDialog):
    """About dialog showing application information"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About C2 Hunter")
        self.setFixedSize(400, 300)
        
        self.init_ui()
        apply_stylesheet(self, theme='dark_teal.xml')
        
    def init_ui(self):
        layout = QVBoxLayout()
      
        title = QLabel("C2 Hunter")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
     
        version = QLabel("Version 1.0.0")
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)
     
        desc = QLabel(
            "A tool for detecting Command and Control (C2) servers\n"
            "by analyzing domain relationships with suspicious IPs."
        )
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        layout.addWidget(desc)
    
        credits = QTextBrowser()
        credits.setPlainText(
            "Developed by: [EmperorYetiandi]\n\n"
            "Libraries used:\n"
            "- PyQt5\n"
            "- VirusTotal API\n"
            "- PyVis\n"
            "- qt-material\n\n"
            "License: MIT"
        )
        credits.setFrameStyle(0)
        credits.setOpenExternalLinks(True)
        layout.addWidget(credits)
       
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        
        self.setLayout(layout)