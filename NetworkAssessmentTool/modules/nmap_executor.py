"""
Nmap Executor Module
Executes Nmap scans using subprocess and manages scan configurations
"""

import subprocess
import platform
import shutil
from datetime import datetime


class NmapExecutor:
    """
    Manages execution of Nmap scans with different techniques
    Uses ONLY basic commands suitable for educational purposes
    """
    
    # Scan types covered in the course
    SCAN_TYPES = {
        'ping': {
            'name': 'Host Discovery (Ping Scan)',
            'command': '-sn',
            'description': 'Identifies which hosts are alive on the network without scanning ports. Sends ICMP echo requests.',
            'requires_root': False,
            'security_purpose': 'Reconnaissance - First step to map active hosts before deeper scanning'
        },
        'tcp_connect': {
            'name': 'TCP Connect Scan',
            'command': '-sT',
            'description': 'Establishes full TCP connection to each port. Most basic and detectable scan type.',
            'requires_root': False,
            'security_purpose': 'Reconnaissance - Identifies open TCP ports by completing the 3-way handshake'
        },
        'syn_stealth': {
            'name': 'TCP SYN Scan (Stealth)',
            'command': '-sS',
            'description': 'Half-open scan that sends SYN packets without completing the handshake. More stealthy.',
            'requires_root': False,
            'security_purpose': 'Reconnaissance - Stealthier port detection, less likely to be logged'
        },
        'service_version': {
            'name': 'Service Version Detection',
            'command': '-sV',
            'description': 'Detects versions of services running on open ports.',
            'requires_root': False,
            'security_purpose': 'Enumeration - Identifies specific software versions for vulnerability assessment'
        },
        'top_ports': {
            'name': 'Top Ports Scan',
            'command': '--top-ports 20',
            'description': 'Scans only the 20 most commonly used ports for faster results.',
            'requires_root': False,
            'security_purpose': 'Reconnaissance - Quick scan of most likely vulnerable services'
        }
    }
    
    def __init__(self):
        self.nmap_path = self._find_nmap()
        self.results = []
    
    def _find_nmap(self):
        """
        Locate Nmap executable on the system
        
        Returns:
            str: Path to Nmap executable or 'nmap' if in PATH
        """
        # Check if nmap is in PATH
        nmap_executable = shutil.which('nmap')
        if nmap_executable:
            return nmap_executable
        
        # Common Windows installation paths
        if platform.system() == 'Windows':
            common_paths = [
                r'C:\Program Files (x86)\Nmap\nmap.exe',
                r'C:\Program Files\Nmap\nmap.exe',
            ]
            for path in common_paths:
                if shutil.os.path.exists(path):
                    return path
        
        # If not found, return 'nmap' and hope it's in PATH
        return 'nmap'
    
    def check_nmap_installed(self):
        """
        Verify that Nmap is installed and accessible
        
        Returns:
            bool: True if Nmap is available, False otherwise
        """
        try:
            result = subprocess.run(
                [self.nmap_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def get_nmap_version(self):
        """
        Get installed Nmap version
        
        Returns:
            str: Nmap version string or error message
        """
        try:
            result = subprocess.run(
                [self.nmap_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Extract version from first line
                first_line = result.stdout.split('\n')[0]
                return first_line
            return "Unable to determine version"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def execute_scan(self, target, scan_type='tcp_connect', port_range=None, timeout=300):
        """
        Execute an Nmap scan on a target
        
        Args:
            target (str): IP address, domain, or CIDR notation
            scan_type (str): Type of scan from SCAN_TYPES
            port_range (str): Port specification (e.g., '80', '1-100', '22,80,443')
            timeout (int): Command timeout in seconds
            
        Returns:
            dict: Scan result with metadata and output
        """
        if scan_type not in self.SCAN_TYPES:
            raise ValueError(f"Invalid scan type: {scan_type}")
        
        scan_info = self.SCAN_TYPES[scan_type]
        
        # Build Nmap command
        # Using basic command structure from course materials
        cmd = [self.nmap_path]
        
        # Add scan type flag
        cmd.append(scan_info['command'])
        
        # Add port specification if provided (from Port Specification section)
        if port_range and scan_type != 'ping':
            cmd.extend(['-p', port_range])
        
        # Add verbosity for better output (from course materials)
        cmd.append('-v')
        
        # Skip ping for hosts that might block it (from Host Discovery section)
        if scan_type != 'ping':
            cmd.append('-Pn')
        
        # Add target
        cmd.append(target)
        
        # Prepare result structure
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
        
        print(f"\n[*] Executing: {scan_info['name']}")
        print(f"[*] Target: {target}")
        print(f"[*] Command: {' '.join(cmd)}")
        print(f"[*] Security Purpose: {scan_info['security_purpose']}")
        print(f"[*] Running scan (timeout: {timeout}s)...\n")
        
        try:
            # Execute Nmap command using subprocess
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            result['output'] = process.stdout
            result['error'] = process.stderr
            result['success'] = (process.returncode == 0)
            
            if result['success']:
                print(f"[✓] Scan completed successfully")
            else:
                print(f"[✗] Scan failed with return code: {process.returncode}")
                if result['error']:
                    print(f"[!] Error: {result['error']}")
            
        except subprocess.TimeoutExpired:
            result['error'] = f"Scan timed out after {timeout} seconds"
            print(f"[✗] {result['error']}")
        except FileNotFoundError:
            result['error'] = "Nmap executable not found. Please install Nmap."
            print(f"[✗] {result['error']}")
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            print(f"[✗] {result['error']}")
        
        self.results.append(result)
        return result
    
    def execute_multi_scan(self, target, scan_types=['ping', 'tcp_connect'], port_range='1-1000'):
        """
        Execute multiple scan types on a single target
        Demonstrates layered reconnaissance approach
        
        Args:
            target (str): Target to scan
            scan_types (list): List of scan type keys
            port_range (str): Port specification for port scans
            
        Returns:
            list: List of scan results
        """
        results = []
        
        print(f"\n{'='*60}")
        print(f"Multi-Scan Assessment: {target}")
        print(f"{'='*60}")
        
        for scan_type in scan_types:
            # Skip port range for ping scans
            pr = port_range if scan_type != 'ping' else None
            result = self.execute_scan(target, scan_type, pr)
            results.append(result)
            
            # Brief pause between scans (polite scanning)
            if len(scan_types) > 1:
                print("\n[*] Waiting before next scan (polite delay)...")
                import time
                time.sleep(2)
        
        return results
    
    def get_all_results(self):
        """
        Get all scan results collected
        
        Returns:
            list: All scan results
        """
        return self.results
    
    def display_scan_types(self):
        """
        Display available scan types with educational information
        """
        print("\n" + "="*70)
        print("Available Scan Types (From Course Materials)")
        print("="*70 + "\n")
        
        for key, info in self.SCAN_TYPES.items():
            print(f"Scan Type: {key}")
            print(f"  Name: {info['name']}")
            print(f"  Command: {info['command']}")
            print(f"  Description: {info['description']}")
            print(f"  Requires Root: {'Yes' if info['requires_root'] else 'No'}")
            print(f"  Security Purpose: {info['security_purpose']}")
            print()


# Example usage and testing
if __name__ == "__main__":
    executor = NmapExecutor()
    
    # Check if Nmap is installed
    if executor.check_nmap_installed():
        print(f"✓ Nmap found: {executor.get_nmap_version()}")
        executor.display_scan_types()
    else:
        print("✗ Nmap is not installed or not in PATH")
        print("Please install Nmap from https://nmap.org/download.html")
