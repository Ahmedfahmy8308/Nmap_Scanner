"""
Network Assessment Tool - GUI Application
Modern graphical interface using CustomTkinter
"""

import customtkinter as ctk
from tkinter import filedialog, scrolledtext
import threading
import sys
import os
from datetime import datetime
import queue

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.input_handler import InputHandler
from modules.nmap_executor import NmapExecutor
from modules.output_parser import OutputParser
from modules.pdf_generator import PDFReportGenerator


class NetworkAssessmentGUI:
    """
    Modern GUI for Network Assessment Tool using CustomTkinter
    """
    
    def __init__(self):
        # Set appearance mode and color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("Network Security Assessment Tool")
        self.root.geometry("1200x800")
        
        # Initialize backend components
        self.input_handler = InputHandler()
        self.nmap_executor = NmapExecutor()
        self.output_parser = OutputParser()
        self.pdf_generator = PDFReportGenerator()
        
        # State variables
        self.targets = []
        self.scan_results = []
        self.is_scanning = False
        self.current_process = None  # Track running Nmap process
        self.output_queue = queue.Queue()
        
        # Build GUI
        self.build_gui()
        
        # Start output processor
        self.process_output()
        
    def build_gui(self):
        """
        Build the complete GUI layout
        """
        # Configure grid
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Left sidebar
        self.create_sidebar()
        
        # Main content area
        self.create_main_content()
        
    def create_sidebar(self):
        """
        Create left sidebar with controls
        """
        sidebar = ctk.CTkFrame(self.root, width=300, corner_radius=0)
        sidebar.grid(row=0, column=0, rowspan=4, sticky="nsew")
        sidebar.grid_rowconfigure(17, weight=1)
        
        # Logo/Title
        title_label = ctk.CTkLabel(
            sidebar,
            text="Network Assessment\nTool",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.grid(row=0, column=0, padx=20, pady=(20, 30))
        
        # Target Input Section
        section_label = ctk.CTkLabel(
            sidebar,
            text="Target Specification",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        section_label.grid(row=2, column=0, padx=20, pady=(10, 5), sticky="w")
        
        # Target entry
        self.target_entry = ctk.CTkEntry(
            sidebar,
            placeholder_text="Enter IP or domain",
            width=260
        )
        self.target_entry.grid(row=3, column=0, padx=20, pady=5)
        
        # Add target button
        add_btn = ctk.CTkButton(
            sidebar,
            text="Add Target",
            command=self.add_target,
            width=260
        )
        add_btn.grid(row=4, column=0, padx=20, pady=5)
        
        # Load from file button
        load_btn = ctk.CTkButton(
            sidebar,
            text="Load from File",
            command=self.load_targets_from_file,
            width=260,
            fg_color="gray40",
            hover_color="gray30"
        )
        load_btn.grid(row=5, column=0, padx=20, pady=5)
        
        # Scan Configuration Section
        scan_label = ctk.CTkLabel(
            sidebar,
            text="Scan Configuration",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        scan_label.grid(row=6, column=0, padx=20, pady=(20, 5), sticky="w")
        
        # Scan type checkboxes
        self.scan_vars = {}
        scan_types = [
            ("ping", "Host Discovery (Ping)"),
            ("tcp_connect", "TCP Connect Scan"),
            ("syn_stealth", "TCP SYN (Stealth)"),
            ("service_version", "Service Detection"),
            ("top_ports", "Top Ports Scan")
        ]
        
        for idx, (key, label) in enumerate(scan_types):
            var = ctk.BooleanVar(value=False)
            checkbox = ctk.CTkCheckBox(
                sidebar,
                text=label,
                variable=var,
                font=ctk.CTkFont(size=11)
            )
            checkbox.grid(row=7+idx, column=0, padx=20, pady=3, sticky="w")
            self.scan_vars[key] = var
        
        # Port range
        port_label = ctk.CTkLabel(
            sidebar,
            text="Port Range:",
            font=ctk.CTkFont(size=11)
        )
        port_label.grid(row=12, column=0, padx=20, pady=(15, 2), sticky="w")
        
        self.port_entry = ctk.CTkEntry(
            sidebar,
            placeholder_text="1-1000",
            width=260
        )
        self.port_entry.insert(0, "1-1000")
        self.port_entry.grid(row=13, column=0, padx=20, pady=2)
        
        # Action Buttons
        self.start_btn = ctk.CTkButton(
            sidebar,
            text="▶ Start Assessment",
            command=self.start_assessment,
            width=260,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2b6cb0",
            hover_color="#1e4a7a"
        )
        self.start_btn.grid(row=14, column=0, padx=20, pady=(20, 5))
        
        self.stop_btn = ctk.CTkButton(
            sidebar,
            text="⬛ Stop Scan",
            command=self.stop_scan,
            width=260,
            state="disabled",
            fg_color="#c53030",
            hover_color="#9b2c2c"
        )
        self.stop_btn.grid(row=15, column=0, padx=20, pady=5)
        
        # Clear button
        clear_btn = ctk.CTkButton(
            sidebar,
            text="Clear All",
            command=self.clear_all,
            width=260,
            fg_color="gray40",
            hover_color="gray30"
        )
        clear_btn.grid(row=16, column=0, padx=20, pady=5)
        
    def create_main_content(self):
        """
        Create main content area with tabs
        """
        # Main frame
        main_frame = ctk.CTkFrame(self.root)
        main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Status bar at top
        self.status_label = ctk.CTkLabel(
            main_frame,
            text="Ready to scan",
            font=ctk.CTkFont(size=12),
            anchor="w"
        )
        self.status_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        
        # Tabview
        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # Create tabs
        self.tabview.add("Targets")
        self.tabview.add("Console Output")
        self.tabview.add("Results")
        
        # Configure tab content
        self.setup_targets_tab()
        self.setup_console_tab()
        self.setup_results_tab()
        
    def setup_targets_tab(self):
        """
        Setup targets display tab
        """
        tab = self.tabview.tab("Targets")
        
        label = ctk.CTkLabel(
            tab,
            text="Target List",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        label.pack(pady=10)
        
        # Targets listbox
        self.targets_text = ctk.CTkTextbox(tab, wrap="word", font=ctk.CTkFont(size=12))
        self.targets_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.update_targets_display()
        
    def setup_console_tab(self):
        """
        Setup console output tab
        """
        tab = self.tabview.tab("Console Output")
        
        # Console output
        self.console_output = ctk.CTkTextbox(
            tab,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11)
        )
        self.console_output.pack(fill="both", expand=True, padx=10, pady=10)
        
    def setup_results_tab(self):
        """
        Setup results display tab
        """
        tab = self.tabview.tab("Results")
        
        # Results display
        self.results_text = ctk.CTkTextbox(
            tab,
            wrap="word",
            font=ctk.CTkFont(size=11)
        )
        self.results_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Generate report button
        self.report_btn = ctk.CTkButton(
            tab,
            text="📄 Generate PDF Report",
            command=self.generate_pdf_report,
            height=40,
            font=ctk.CTkFont(size=14),
            state="disabled"
        )
        self.report_btn.pack(pady=10)
        
    def add_target(self):
        """
        Add target from entry field
        """
        target = self.target_entry.get().strip()
        if not target:
            self.log_console("⚠️ Please enter a target")
            return
        
        if self.input_handler.validate_target(target):
            self.targets.append(target)
            self.target_entry.delete(0, 'end')
            self.update_targets_display()
            self.log_console(f"✓ Added target: {target}")
        else:
            self.log_console(f"✗ Invalid target: {target}")
            
    def load_targets_from_file(self):
        """
        Load targets from file
        """
        filepath = filedialog.askopenfilename(
            title="Select Targets File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                loaded = self.input_handler.read_from_file(filepath)
                self.targets.extend(loaded)
                self.update_targets_display()
                self.log_console(f"✓ Loaded {len(loaded)} target(s) from file")
            except Exception as e:
                self.log_console(f"✗ Error loading file: {str(e)}")
                
    def update_targets_display(self):
        """
        Update targets list display
        """
        self.targets_text.configure(state="normal")
        self.targets_text.delete("1.0", "end")
        
        if not self.targets:
            self.targets_text.insert("1.0", "No targets added yet.\n\nAdd targets manually or load from a file.")
        else:
            self.targets_text.insert("1.0", f"Total Targets: {len(self.targets)}\n\n")
            for idx, target in enumerate(self.targets, 1):
                self.targets_text.insert("end", f"{idx}. {target}\n")
        
        self.targets_text.configure(state="disabled")
        
    def log_console(self, message):
        """
        Add message to console output
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output_queue.put(f"[{timestamp}] {message}")
        
    def process_output(self):
        """
        Process output queue and update console
        """
        try:
            while True:
                message = self.output_queue.get_nowait()
                self.console_output.insert("end", message + "\n")
                self.console_output.see("end")
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_output)
        
    def start_assessment(self):
        """
        Start the network assessment
        """
        # Validate
        if not self.targets:
            self.log_console("✗ No targets specified!")
            return
        
        # Get selected scan types
        selected_scans = [key for key, var in self.scan_vars.items() if var.get()]
        if not selected_scans:
            self.log_console("✗ No scan types selected!")
            return
        
        port_range = self.port_entry.get().strip() or "1-1000"
        
        # Disable controls
        self.is_scanning = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_label.configure(text="🔍 Scanning in progress...")
        
        # Clear previous results
        self.scan_results = []
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.configure(state="disabled")
        
        # Start scan in separate thread
        scan_thread = threading.Thread(
            target=self.run_assessment,
            args=(self.targets.copy(), selected_scans, port_range),
            daemon=True
        )
        scan_thread.start()
        
    def run_assessment(self, targets, scan_types, port_range):
        """
        Run the assessment in background thread
        """
        self.log_console("="*60)
        self.log_console("🚀 STARTING NETWORK ASSESSMENT")
        self.log_console("="*60)
        self.log_console(f"Targets: {len(targets)}")
        self.log_console(f"Scan types: {', '.join(scan_types)}")
        self.log_console(f"Port range: {port_range}")
        self.log_console("")
        
        try:
            for idx, target in enumerate(targets, 1):
                if not self.is_scanning:
                    self.log_console("\n⚠️ Scan stopped by user")
                    break
                
                self.log_console(f"\n{'='*60}")
                self.log_console(f"Target {idx}/{len(targets)}: {target}")
                self.log_console(f"{'='*60}")
                
                for scan_type in scan_types:
                    if not self.is_scanning:
                        break
                    
                    pr = port_range if scan_type != 'ping' else None
                    
                    self.log_console(f"\n▶ Running {scan_type} scan...")
                    
                    # Execute scan with process tracking
                    result = self.execute_scan_with_tracking(
                        target=target,
                        scan_type=scan_type,
                        port_range=pr,
                        timeout=300
                    )
                    
                    # Redirect Nmap output to GUI
                    if result.get('success'):
                        self.log_console("✓ Scan completed successfully")
                    else:
                        self.log_console(f"✗ Scan failed: {result.get('error', 'Unknown error')}")
                    
                    self.scan_results.append(result)
                    
                    # Brief pause
                    import time
                    time.sleep(1)
            
            # Analysis
            self.log_console("\n" + "="*60)
            self.log_console("📊 ANALYZING RESULTS...")
            self.log_console("="*60)
            
            parsed_results = self.output_parser.parse_multiple_results(self.scan_results)
            summary = self.output_parser.generate_summary(parsed_results)
            
            self.log_console(f"✓ Hosts up: {summary.get('hosts_up', 0)}")
            self.log_console(f"✓ Open ports found: {summary.get('total_open_ports', 0)}")
            self.log_console(f"✓ Services detected: {len(summary.get('unique_services', []))}")
            
            # Display results
            self.display_results(parsed_results, summary)
            
            self.log_console("\n✅ Assessment complete!")
            self.output_queue.put("\n" + "="*60)
            
        except Exception as e:
            self.log_console(f"\n✗ Error during assessment: {str(e)}")
        
        finally:
            # Re-enable controls
            self.root.after(0, self.finish_scan)
            
    def display_results(self, parsed_results, summary):
        """
        Display results in results tab
        """
        def update_ui():
            self.results_text.configure(state="normal")
            self.results_text.delete("1.0", "end")
            
            # Summary
            self.results_text.insert("end", "="*60 + "\n")
            self.results_text.insert("end", "ASSESSMENT SUMMARY\n")
            self.results_text.insert("end", "="*60 + "\n\n")
            
            self.results_text.insert("end", f"Total Scans: {summary.get('total_scans', 0)}\n")
            self.results_text.insert("end", f"Successful: {summary.get('successful_scans', 0)}\n")
            self.results_text.insert("end", f"Failed: {summary.get('failed_scans', 0)}\n")
            self.results_text.insert("end", f"Hosts Up: {summary.get('hosts_up', 0)}\n")
            self.results_text.insert("end", f"Open Ports: {summary.get('total_open_ports', 0)}\n")
            
            if summary.get('unique_services'):
                self.results_text.insert("end", f"\nServices: {', '.join(summary.get('unique_services', []))}\n")
            
            # Detailed findings
            for result in parsed_results:
                self.results_text.insert("end", "\n" + "="*60 + "\n")
                self.results_text.insert("end", f"Target: {result.get('target')}\n")
                self.results_text.insert("end", f"Scan: {result.get('scan_name')}\n")
                self.results_text.insert("end", f"Status: {result.get('host_status', 'unknown').upper()}\n")
                self.results_text.insert("end", "-"*60 + "\n")
                
                ports = result.get('ports', [])
                open_ports = [p for p in ports if p.get('state') == 'open']
                
                if open_ports:
                    self.results_text.insert("end", f"\nOpen Ports: {len(open_ports)}\n")
                    for port in open_ports:
                        version = port.get('version', '')
                        self.results_text.insert("end", 
                            f"  • Port {port.get('port')}/{port.get('protocol')} - "
                            f"{port.get('service')} {version}\n"
                        )
                else:
                    self.results_text.insert("end", "\nNo open ports found.\n")
            
            self.results_text.configure(state="disabled")
            self.report_btn.configure(state="normal")
            
        self.root.after(0, update_ui)
        
    def execute_scan_with_tracking(self, target, scan_type, port_range, timeout):
        """
        Execute scan while tracking the process for interruption
        """
        import subprocess
        
        if scan_type not in self.nmap_executor.SCAN_TYPES:
            return {'success': False, 'error': 'Invalid scan type'}
        
        scan_info = self.nmap_executor.SCAN_TYPES[scan_type]
        
        # Build Nmap command (same as executor)
        cmd = [self.nmap_executor.nmap_path]
        cmd.append(scan_info['command'])
        
        if port_range and scan_type != 'ping':
            cmd.extend(['-p', port_range])
        
        cmd.append('-v')
        
        if scan_type != 'ping':
            cmd.append('-Pn')
        
        cmd.append(target)
        
        result = {
            'target': target,
            'scan_type': scan_type,
            'scan_name': scan_info['name'],
            'command': ' '.join(cmd),
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'output': '',
            'error': '',
            'security_context': scan_info['security_purpose']
        }
        
        try:
            # Start process
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for completion or interruption
            try:
                stdout, stderr = self.current_process.communicate(timeout=timeout)
                result['output'] = stdout
                result['error'] = stderr
                result['success'] = (self.current_process.returncode == 0)
            except subprocess.TimeoutExpired:
                self.current_process.kill()
                result['error'] = f"Scan timed out after {timeout} seconds"
                self.log_console(f"[✗] {result['error']}")
            
            self.current_process = None
            
        except Exception as e:
            result['error'] = f"Error: {str(e)}"
            self.current_process = None
        
        return result
    
    def stop_scan(self):
        """
        Stop the current scan
        """
        self.is_scanning = False
        self.log_console("\n⚠️ Stopping scan...")
        
        # Kill the running Nmap process if it exists
        if self.current_process and self.current_process.poll() is None:
            self.log_console("⚠️ Terminating Nmap process...")
            try:
                self.current_process.terminate()
                import time
                time.sleep(0.5)
                if self.current_process.poll() is None:
                    self.current_process.kill()
                self.log_console("✓ Nmap process terminated")
            except Exception as e:
                self.log_console(f"✗ Error terminating process: {str(e)}")
            finally:
                self.current_process = None
        
    def finish_scan(self):
        """
        Cleanup after scan finishes
        """
        self.is_scanning = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_label.configure(text="✅ Scan complete - Ready for next assessment")
        
    def generate_pdf_report(self):
        """
        Generate PDF report from results
        """
        if not self.scan_results:
            self.log_console("✗ No results to generate report from")
            return
        
        # Ask for save location
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=f"network_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        
        if not filepath:
            return
        
        self.log_console("\n📄 Generating PDF report...")
        self.status_label.configure(text="📄 Generating PDF report...")
        
        # Generate in thread
        def generate():
            try:
                parsed_results = self.output_parser.parse_multiple_results(self.scan_results)
                summary = self.output_parser.generate_summary(parsed_results)
                
                success = self.pdf_generator.generate_report(parsed_results, summary, filepath)
                
                if success:
                    self.log_console(f"✅ Report saved: {filepath}")
                    self.root.after(0, lambda: self.status_label.configure(text="✅ Report generated successfully"))
                else:
                    self.log_console("✗ Failed to generate report")
                    self.root.after(0, lambda: self.status_label.configure(text="✗ Report generation failed"))
            except Exception as e:
                self.log_console(f"✗ Error generating report: {str(e)}")
        
        threading.Thread(target=generate, daemon=True).start()
        
    def clear_all(self):
        """
        Clear all targets and results
        """
        self.targets = []
        self.scan_results = []
        self.update_targets_display()
        
        self.console_output.delete("1.0", "end")
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.configure(state="disabled")
        
        self.report_btn.configure(state="disabled")
        self.status_label.configure(text="Ready to scan")
        self.log_console("🗑️ Cleared all targets and results")
        
    def run(self):
        """
        Start the GUI main loop
        """
        # Check prerequisites
        if not self.nmap_executor.check_nmap_installed():
            self.log_console("⚠️ WARNING: Nmap is not installed or not in PATH!")
            self.log_console("Please install Nmap from: https://nmap.org/download.html")
        else:
            version = self.nmap_executor.get_nmap_version()
            self.log_console(f"✓ {version}")
            self.log_console("Ready to perform security assessments\n")
        
        # Bring window to front
        self.root.lift()
        self.root.focus_force()
        self.root.attributes('-topmost', True)
        self.root.after(100, lambda: self.root.attributes('-topmost', False))
        
        self.root.mainloop()


def main():
    """
    Main entry point for GUI
    """
    app = NetworkAssessmentGUI()
    app.run()


if __name__ == "__main__":
    main()
