from datetime import datetime
from PyQt5.QtGui import QFontDatabase
import os
import sys
import webbrowser
from PyQt5.QtWidgets import (QMainWindow, QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
                             QFileDialog, QTabWidget, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QGroupBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QColor
from qt_material import apply_stylesheet

from core.fetcher import VirusTotalFetcher
from core.analyzer import DomainAnalyzer
from core.visualizer import ThreatVisualizer
from core.reporter import ReportGenerator
from config import Config

class AnalysisThread(QThread):
    update_progress = pyqtSignal(int, str)
    analysis_complete = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address

    def run(self):
        try:
            self.update_progress.emit(0, "Initializing analysis...")
            
            fetcher = VirusTotalFetcher()
            
            self.update_progress.emit(10, "Fetching related domains...")
            domains = fetcher.get_related_domains(self.ip_address)
            
            if not domains:
                self.error_occurred.emit("No domains found for this IP address")
                return
                
            self.update_progress.emit(20, f"Found {len(domains)} domains. Analyzing...")
            
            domain_data_list = []
            total_domains = len(domains)
            
            for i, domain in enumerate(domains):
                self.update_progress.emit(
                    20 + int(70 * i / total_domains),
                    f"Analyzing domain {i+1}/{total_domains}: {domain}"
                )
                
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
            
            self.update_progress.emit(95, "Finalizing results...")
            self.analysis_complete.emit(domain_data_list)
            self.update_progress.emit(100, "Analysis complete!")
            
        except Exception as e:
            self.error_occurred.emit(f"Analysis failed: {str(e)}")

class C2HunterGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("C2 Hunter - By EmperorYetiandi")
        self.setGeometry(100, 100, 1200, 800)
        
        self.current_ip = ""
        self.domain_data = []
        
        self.init_ui()
        self.show()
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        header = QLabel("C2 Hunter - Command & Control Detection Tool")
        header.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 15px;")
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)
       
        input_group = QGroupBox("Target Information")
        input_layout = QHBoxLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address to analyze (e.g., 8.8.8.8)")
        self.ip_input.setStyleSheet("padding: 8px;")
        
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.setStyleSheet("padding: 8px 15px;")
        self.analyze_btn.clicked.connect(self.start_analysis)
        
        input_layout.addWidget(self.ip_input)
        input_layout.addWidget(self.analyze_btn)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
     
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("QProgressBar { height: 25px; }")
        main_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        main_layout.addWidget(self.status_label)
      
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
       
        self.results_tab = QWidget()
        self.results_layout = QVBoxLayout(self.results_tab)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Domain", "Risk Level", "Score", "Malicious", "Suspicious", "C2 Detected"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        self.results_layout.addWidget(self.results_table)
        self.tabs.addTab(self.results_tab, "Results")
      
        self.log_tab = QWidget()
        self.log_layout = QVBoxLayout(self.log_tab)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_layout.addWidget(self.log_text)
        
        self.tabs.addTab(self.log_tab, "Analysis Log")
     
        actions_group = QGroupBox("Actions")
        actions_layout = QHBoxLayout()
        
        self.visualize_btn = QPushButton("Visualize")
        self.visualize_btn.setStyleSheet("padding: 8px 15px;")
        self.visualize_btn.clicked.connect(self.visualize_results)
        self.visualize_btn.setEnabled(False)
        
        self.export_json_btn = QPushButton("Export JSON")
        self.export_json_btn.setStyleSheet("padding: 8px 15px;")
        self.export_json_btn.clicked.connect(self.export_json)
        self.export_json_btn.setEnabled(False)
        
        self.export_md_btn = QPushButton("Export Markdown")
        self.export_md_btn.setStyleSheet("padding: 8px 15px;")
        self.export_md_btn.clicked.connect(self.export_markdown)
        self.export_md_btn.setEnabled(False)
        
        actions_layout.addWidget(self.visualize_btn)
        actions_layout.addWidget(self.export_json_btn)
        actions_layout.addWidget(self.export_md_btn)
        actions_group.setLayout(actions_layout)
        main_layout.addWidget(actions_group)
        
    def start_analysis(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address to analyze")
            return
            
        self.current_ip = ip
        self.domain_data = []
        self.log_text.clear()
        self.results_table.setRowCount(0)
        
        self.log(f"Starting analysis for IP: {ip}")
        
        self.analyze_btn.setEnabled(False)
        self.visualize_btn.setEnabled(False)
        self.export_json_btn.setEnabled(False)
        self.export_md_btn.setEnabled(False)
        
        self.thread = AnalysisThread(ip)
        self.thread.update_progress.connect(self.update_progress)
        self.thread.analysis_complete.connect(self.analysis_complete)
        self.thread.error_occurred.connect(self.analysis_error)
        self.thread.start()
        
    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.log(message)
        
    def analysis_complete(self, domain_data_list):
        self.domain_data = domain_data_list
        self.analyze_btn.setEnabled(True)
        self.visualize_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)
        self.export_md_btn.setEnabled(True)
        
        self.display_results(domain_data_list)
        self.log(f"Analysis completed. Found {len(domain_data_list)} domains.")
        
    def analysis_error(self, message):
        self.log(f"Error: {message}")
        self.progress_bar.setValue(0)
        self.status_label.setText("Analysis failed")
        self.analyze_btn.setEnabled(True)
        QMessageBox.critical(self, "Analysis Error", message)
        
    def display_results(self, domain_data_list):
        self.results_table.setRowCount(len(domain_data_list))
        
        risk_colors = {
            "critical": QColor(255, 71, 87),
            "high": QColor(255, 107, 129),
            "medium": QColor(255, 165, 2),
            "low": QColor(236, 204, 104),
            "clean": QColor(46, 213, 115),
            "unknown": QColor(164, 176, 190)
        }
        
        for row, (domain, data) in enumerate(domain_data_list):
            domain_item = QTableWidgetItem(domain)
            self.results_table.setItem(row, 0, domain_item)
        
            risk = data.get("risk", "unknown")
            risk_item = QTableWidgetItem(risk.upper())
            risk_item.setBackground(risk_colors.get(risk, risk_colors["unknown"]))
            self.results_table.setItem(row, 1, risk_item)
       
            score_item = QTableWidgetItem(str(data.get("score", 0)))
            self.results_table.setItem(row, 2, score_item)
         
            malicious_item = QTableWidgetItem(str(data.get("malicious", 0)))
            self.results_table.setItem(row, 3, malicious_item)
        
            suspicious_item = QTableWidgetItem(str(data.get("suspicious", 0)))
            self.results_table.setItem(row, 4, suspicious_item)
         
            c2_item = QTableWidgetItem("Yes" if data.get("c2", False) else "No")
            self.results_table.setItem(row, 5, c2_item)
            
        self.results_table.sortItems(2, Qt.DescendingOrder)  # Sort by score
        
    def visualize_results(self):
        if not self.domain_data:
            return
            
        output_file = os.path.join(Config.OUTPUT_DIR, f"c2_graph_{self.current_ip}.html")
        
        try:
            ThreatVisualizer.create_graph(self.current_ip, self.domain_data, output_file)
            webbrowser.open(output_file)
            self.log(f"Visualization saved to: {output_file}")
        except Exception as e:
            self.log(f"Error generating visualization: {str(e)}")
            QMessageBox.critical(self, "Visualization Error", f"Failed to generate visualization: {str(e)}")
            
    def export_json(self):
        if not self.domain_data:
            return
            
        default_path = os.path.join(Config.OUTPUT_DIR, f"c2_report_{self.current_ip}.json")
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Report", default_path, "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                ReportGenerator.generate_json_report(self.current_ip, self.domain_data, os.path.dirname(file_path))
                self.log(f"JSON report saved to: {file_path}")
                QMessageBox.information(self, "Export Successful", "JSON report generated successfully")
            except Exception as e:
                self.log(f"Error exporting JSON: {str(e)}")
                QMessageBox.critical(self, "Export Error", f"Failed to export JSON: {str(e)}")
                
    def export_markdown(self):
        if not self.domain_data:
            return
            
        default_path = os.path.join(Config.OUTPUT_DIR, f"c2_report_{self.current_ip}.md")
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Markdown Report", default_path, "Markdown Files (*.md)"
        )
        
        if file_path:
            try:
                ReportGenerator.generate_markdown_report(self.current_ip, self.domain_data, os.path.dirname(file_path))
                self.log(f"Markdown report saved to: {file_path}")
                QMessageBox.information(self, "Export Successful", "Markdown report generated successfully")
            except Exception as e:
                self.log(f"Error exporting Markdown: {str(e)}")
                QMessageBox.critical(self, "Export Error", f"Failed to export Markdown: {str(e)}")
                
    def log(self, message):
        self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

def main():
    app = QApplication(sys.argv)
    
    apply_stylesheet(app, theme='dark_teal.xml')
    
    app.setWindowIcon(QIcon(os.path.join("assets", "icons", "c2hunter.png")))
    
    gui = C2HunterGUI()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()