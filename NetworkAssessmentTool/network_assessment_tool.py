"""
Network Assessment Tool - Main Application

This tool performs basic network reconnaissance using Nmap and generates
professional PDF reports.

Date: December 2025
"""

import sys
import os
from datetime import datetime
import argparse

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.input_handler import InputHandler
from modules.nmap_executor import NmapExecutor
from modules.output_parser import OutputParser
from modules.pdf_generator import PDFReportGenerator


class NetworkAssessmentTool:
    """
    Main application class that orchestrates the network assessment process
    """
    
    def __init__(self):
        self.input_handler = InputHandler()
        self.nmap_executor = NmapExecutor()
        self.output_parser = OutputParser()
        self.pdf_generator = PDFReportGenerator()
        self.scan_results = []
        self.parsed_results = []
    
    def display_banner(self):
        """
        Display application banner
        """
        banner = """
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║         Network Security Assessment Tool v1.0                      ║
║                                                                    ║
║         IMPORTANT: Use only on authorized targets!                 ║
║         Unauthorized network scanning is illegal.                  ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    def check_prerequisites(self):
        """
        Check if all prerequisites are met
        
        Returns:
            bool: True if all checks pass, False otherwise
        """
        print("\n[*] Checking prerequisites...")
        
        # Check Nmap installation
        if not self.nmap_executor.check_nmap_installed():
            print("[✗] Nmap is not installed or not in PATH")
            print("    Please install Nmap from: https://nmap.org/download.html")
            return False
        
        version = self.nmap_executor.get_nmap_version()
        print(f"[✓] Nmap found: {version}")
        
        return True
    
    def configure_scan(self):
        """
        Interactive scan configuration
        
        Returns:
            dict: Scan configuration
        """
        print("\n" + "="*70)
        print("SCAN CONFIGURATION")
        print("="*70)
        
        config = {
            'scan_types': [],
            'port_range': '1-1000',
            'output_dir': 'output'
        }
        
        # Display available scan types
        print("\nAvailable Scan Types:")
        scan_types = list(self.nmap_executor.SCAN_TYPES.keys())
        for idx, scan_type in enumerate(scan_types, 1):
            info = self.nmap_executor.SCAN_TYPES[scan_type]
            root_req = " [Requires Root]" if info['requires_root'] else ""
            print(f"  {idx}. {info['name']}{root_req}")
        
        # Select scan types
        print("\nSelect scan types to perform (comma-separated numbers, e.g., 1,2,4)")
        print("Or press Enter for default (ping + TCP connect + service version):")
        
        selection = input("Selection: ").strip()
        
        if not selection:
            # No default selection - user must choose
            config['scan_types'] = []
            print("No scan types selected. Please select at least one scan type.")
        else:
            # Parse user selection
            try:
                indices = [int(x.strip()) for x in selection.split(',')]
                config['scan_types'] = [scan_types[i-1] for i in indices if 1 <= i <= len(scan_types)]
                print(f"Selected: {', '.join(config['scan_types'])}")
            except (ValueError, IndexError):
                print("Invalid selection. Using defaults.")
                config['scan_types'] = ['ping', 'tcp_connect', 'service_version']
        
        # Port range configuration
        if any(st not in ['ping'] for st in config['scan_types']):
            print("\nPort Range Configuration:")
            print("  1. Fast scan (top 20 ports)")
            print("  2. Common ports (1-1000)")
            print("  3. Extended scan (1-5000)")
            print("  4. Custom range")
            
            port_choice = input("Select port range [2]: ").strip() or "2"
            
            if port_choice == "1":
                config['port_range'] = None  # Will use --top-ports in scan
                config['scan_types'] = ['top_ports'] + [st for st in config['scan_types'] if st != 'ping']
            elif port_choice == "3":
                config['port_range'] = '1-5000'
            elif port_choice == "4":
                custom_range = input("Enter custom port range (e.g., 80,443,8080 or 1-100): ").strip()
                config['port_range'] = custom_range if custom_range else '1-1000'
            else:
                config['port_range'] = '1-1000'
            
            print(f"Port range: {config['port_range']}")
        
        return config
    
    def get_targets(self):
        """
        Get targets from user (file or console)
        
        Returns:
            list: List of targets
        """
        print("\n" + "="*70)
        print("TARGET SPECIFICATION")
        print("="*70)
        print("\nHow would you like to specify targets?")
        print("  1. Enter manually")
        print("  2. Load from file")
        
        choice = input("Choice [1]: ").strip() or "1"
        
        if choice == "2":
            filepath = input("Enter path to targets file: ").strip()
            try:
                targets = self.input_handler.read_from_file(filepath)
                print(f"\n[✓] Loaded {len(targets)} target(s) from file")
            except FileNotFoundError as e:
                print(f"\n[✗] {str(e)}")
                print("Falling back to manual entry...")
                targets = self.input_handler.read_from_console()
        else:
            targets = self.input_handler.read_from_console()
        
        if not targets:
            print("\n[✗] No targets specified. Exiting.")
            return None
        
        # Display targets
        self.input_handler.display_targets()
        
        # Confirm
        confirm = input("\nProceed with these targets? (yes/no) [yes]: ").strip().lower() or "yes"
        if confirm not in ['yes', 'y']:
            print("Assessment cancelled.")
            return None
        
        return targets
    
    def perform_assessment(self, targets, config):
        """
        Perform the network assessment
        
        Args:
            targets (list): List of targets to scan
            config (dict): Scan configuration
        """
        print("\n" + "="*70)
        print("STARTING NETWORK ASSESSMENT")
        print("="*70)
        print(f"\nTargets: {len(targets)}")
        print(f"Scan types: {', '.join(config['scan_types'])}")
        print(f"Port range: {config.get('port_range', 'N/A')}")
        print("\n[!] Scanning in progress... This may take several minutes.")
        print("[!] Press Ctrl+C to abort (scans already completed will be saved)")
        
        try:
            for idx, target in enumerate(targets, 1):
                print(f"\n{'='*70}")
                print(f"Target {idx}/{len(targets)}: {target}")
                print(f"{'='*70}")
                
                # Execute scans for this target
                for scan_type in config['scan_types']:
                    port_range = config.get('port_range') if scan_type != 'ping' else None
                    
                    result = self.nmap_executor.execute_scan(
                        target=target,
                        scan_type=scan_type,
                        port_range=port_range,
                        timeout=300
                    )
                    
                    self.scan_results.append(result)
                    
                    # Brief pause between scans (polite scanning)
                    if len(config['scan_types']) > 1:
                        import time
                        time.sleep(2)
        
        except KeyboardInterrupt:
            print("\n\n[!] Scan interrupted by user. Generating report with completed scans...")
        
        print(f"\n[✓] Assessment complete. {len(self.scan_results)} scan(s) performed.")
    
    def analyze_results(self):
        """
        Parse and analyze scan results
        """
        print("\n[*] Analyzing results...")
        
        self.parsed_results = self.output_parser.parse_multiple_results(self.scan_results)
        summary = self.output_parser.generate_summary(self.parsed_results)
        
        print(f"[✓] Analysis complete")
        print(f"    - Hosts up: {summary.get('hosts_up', 0)}")
        print(f"    - Open ports found: {summary.get('total_open_ports', 0)}")
        print(f"    - Services detected: {len(summary.get('unique_services', []))}")
        
        return summary
    
    def generate_report(self, summary, output_dir='output'):
        """
        Generate PDF report
        
        Args:
            summary (dict): Summary statistics
            output_dir (str): Output directory
        """
        print("\n[*] Generating PDF report...")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_assessment_report_{timestamp}.pdf"
        output_path = os.path.join(output_dir, filename)
        
        # Generate report
        success = self.pdf_generator.generate_report(
            self.parsed_results,
            summary,
            output_path
        )
        
        if success:
            abs_path = os.path.abspath(output_path)
            print(f"[✓] Report saved to: {abs_path}")
            return output_path
        else:
            print("[✗] Failed to generate report")
            return None
    
    def display_quick_summary(self):
        """
        Display a quick text summary of results
        """
        print("\n" + "="*70)
        print("QUICK SUMMARY")
        print("="*70)
        
        for result in self.parsed_results:
            print(f"\n{self.output_parser.format_parsed_result(result)}")
    
    def run_interactive(self):
        """
        Run the tool in interactive mode
        """
        self.display_banner()
        
        # Legal disclaimer
        print("\n[!] LEGAL DISCLAIMER:")
        print("    This tool should only be used for authorized security assessments.")
        print("    Unauthorized port scanning may be illegal in your jurisdiction.")
        print("    By using this tool, you agree to use it responsibly and legally.")
        
        confirm = input("\n    Do you agree? (yes/no): ").strip().lower()
        if confirm not in ['yes', 'y']:
            print("\nExiting.")
            return
        
        # Check prerequisites
        if not self.check_prerequisites():
            print("\n[✗] Prerequisites not met. Please install required tools.")
            return
        
        # Get targets
        targets = self.get_targets()
        if not targets:
            return
        
        # Configure scan
        config = self.configure_scan()
        
        # Confirm and start
        print("\n" + "="*70)
        print("READY TO START")
        print("="*70)
        input("\nPress Enter to begin assessment...")
        
        # Perform assessment
        self.perform_assessment(targets, config)
        
        # Analyze results
        summary = self.analyze_results()
        
        # Display quick summary
        self.display_quick_summary()
        
        # Generate report
        report_path = self.generate_report(summary, config.get('output_dir', 'output'))
        
        # Final message
        print("\n" + "="*70)
        print("ASSESSMENT COMPLETE")
        print("="*70)
        if report_path:
            print(f"\nYour security assessment report is ready!")
            print(f"Location: {os.path.abspath(report_path)}")
        print("\nThank you for using the Network Assessment Tool!")
        print("Remember: Always obtain proper authorization before scanning!")
        print("="*70 + "\n")
    
    def run_automated(self, targets_file, scan_types, port_range, output_dir):
        """
        Run the tool in automated mode (for scripting)
        
        Args:
            targets_file (str): Path to targets file
            scan_types (list): List of scan types
            port_range (str): Port range
            output_dir (str): Output directory
        """
        self.display_banner()
        
        print("\n[*] Running in automated mode...")
        
        # Check prerequisites
        if not self.check_prerequisites():
            return False
        
        # Load targets
        try:
            targets = self.input_handler.read_from_file(targets_file)
            print(f"[✓] Loaded {len(targets)} target(s)")
        except Exception as e:
            print(f"[✗] Error loading targets: {str(e)}")
            return False
        
        # Configure
        config = {
            'scan_types': scan_types,
            'port_range': port_range,
            'output_dir': output_dir
        }
        
        # Perform assessment
        self.perform_assessment(targets, config)
        
        # Analyze and report
        summary = self.analyze_results()
        report_path = self.generate_report(summary, output_dir)
        
        return report_path is not None


def main():
    """
    Main entry point
    """
    parser = argparse.ArgumentParser(
        description="Network Security Assessment Tool",
        epilog="Example: python network_assessment_tool.py -f targets.txt -s ping,tcp_connect -p 1-1000"
    )
    
    parser.add_argument('-f', '--file', help='Path to targets file')
    parser.add_argument('-s', '--scans', help='Comma-separated scan types (ping,tcp_connect,syn_stealth,service_version,top_ports)')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000, 80,443)', default='1-1000')
    parser.add_argument('-o', '--output', help='Output directory', default='output')
    
    args = parser.parse_args()
    
    tool = NetworkAssessmentTool()
    
    # Check if automated mode (all required args provided)
    if args.file and args.scans:
        scan_types = [s.strip() for s in args.scans.split(',')]
        success = tool.run_automated(args.file, scan_types, args.ports, args.output)
        sys.exit(0 if success else 1)
    else:
        # Interactive mode
        tool.run_interactive()


if __name__ == "__main__":
    main()
