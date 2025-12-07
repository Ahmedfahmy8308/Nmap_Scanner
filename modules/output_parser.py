"""
Output Parser Module
Parses Nmap scan output to extract useful information
"""

import re


class OutputParser:
    """
    Parses Nmap text output to extract structured information
    about hosts, ports, and services
    """
    
    def __init__(self):
        self.parsed_data = {}
    
    def parse_scan_result(self, scan_result):
        """
        Parse a single scan result dictionary from NmapExecutor
        
        Args:
            scan_result (dict): Result dictionary from NmapExecutor
            
        Returns:
            dict: Structured parsed data
        """
        output = scan_result.get('output', '')
        scan_type = scan_result.get('scan_type', 'unknown')
        
        parsed = {
            'target': scan_result.get('target', 'Unknown'),
            'scan_type': scan_type,
            'scan_name': scan_result.get('scan_name', 'Unknown Scan'),
            'timestamp': scan_result.get('timestamp', ''),
            'command': scan_result.get('command', ''),
            'security_context': scan_result.get('security_context', ''),
            'success': scan_result.get('success', False),
            'host_status': 'unknown',
            'ports': [],
            'services': [],
            'warnings': [],
            'raw_output': output
        }
        
        if not parsed['success']:
            parsed['warnings'].append(scan_result.get('error', 'Scan failed'))
            return parsed
        
        # Parse based on scan type
        if scan_type == 'ping':
            parsed.update(self._parse_ping_scan(output))
        elif scan_type in ['tcp_connect', 'syn_stealth', 'top_ports']:
            parsed.update(self._parse_port_scan(output))
        elif scan_type == 'service_version':
            parsed.update(self._parse_service_scan(output))
        else:
            parsed.update(self._parse_generic(output))
        
        return parsed
    
    def _parse_ping_scan(self, output):
        """
        Parse ping/host discovery scan output
        
        Returns:
            dict: Parsed information
        """
        data = {
            'host_status': 'down',
            'latency': None,
            'hosts_up': 0,
            'hosts_down': 0
        }
        
        # Check if host is up
        if re.search(r'Host is up', output, re.IGNORECASE):
            data['host_status'] = 'up'
        
        # Extract latency
        latency_match = re.search(r'Host is up \(([0-9.]+)s latency\)', output)
        if latency_match:
            data['latency'] = latency_match.group(1)
        
        # Extract host statistics
        stats_match = re.search(r'Nmap done: \d+ IP address(?:es)? \((\d+) host(?:s)? up\)', output)
        if stats_match:
            data['hosts_up'] = int(stats_match.group(1))
        
        return data
    
    def _parse_port_scan(self, output):
        """
        Parse port scan output (TCP Connect, SYN, etc.)
        
        Returns:
            dict: Parsed information with port details
        """
        data = {
            'host_status': 'down',
            'ports': [],
            'total_ports_scanned': 0,
            'open_ports_count': 0,
            'closed_ports_count': 0,
            'filtered_ports_count': 0
        }
        
        # Check if host is up
        if re.search(r'Host is up', output, re.IGNORECASE):
            data['host_status'] = 'up'
        
        # Parse PORT section
        # Format: PORT     STATE    SERVICE
        # Example: 22/tcp  open     ssh
        port_pattern = r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)'
        
        for match in re.finditer(port_pattern, output):
            port_num = match.group(1)
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            
            port_info = {
                'port': port_num,
                'protocol': protocol,
                'state': state,
                'service': service
            }
            
            data['ports'].append(port_info)
            
            # Count by state
            if state == 'open':
                data['open_ports_count'] += 1
            elif state == 'closed':
                data['closed_ports_count'] += 1
            elif state == 'filtered':
                data['filtered_ports_count'] += 1
        
        # Extract scan statistics
        scanned_match = re.search(r'Scanned at .+ for (\d+)s', output)
        if scanned_match:
            data['scan_duration'] = scanned_match.group(1) + 's'
        
        return data
    
    def _parse_service_scan(self, output):
        """
        Parse service version detection output
        
        Returns:
            dict: Parsed information with service details
        """
        data = {
            'host_status': 'down',
            'ports': [],
            'services': []
        }
        
        # Check if host is up
        if re.search(r'Host is up', output, re.IGNORECASE):
            data['host_status'] = 'up'
        
        # Parse service version information
        # Format: PORT     STATE SERVICE VERSION
        # Example: 22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
        
        # More flexible pattern to capture version info
        service_pattern = r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.+)?'
        
        lines = output.split('\n')
        in_port_section = False
        
        for line in lines:
            # Identify when we're in the PORT section
            if re.match(r'^PORT\s+STATE\s+SERVICE', line):
                in_port_section = True
                continue
            
            # Stop when we hit a blank line or new section
            if in_port_section and (not line.strip() or line.startswith('Service detection')):
                in_port_section = False
            
            if in_port_section:
                match = re.match(service_pattern, line)
                if match:
                    port_num = match.group(1)
                    protocol = match.group(2)
                    state = match.group(3)
                    service = match.group(4)
                    version = match.group(5).strip() if match.group(5) else 'unknown'
                    
                    port_info = {
                        'port': port_num,
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'version': version
                    }
                    
                    data['ports'].append(port_info)
                    
                    if state == 'open':
                        service_info = {
                            'service': service,
                            'port': port_num,
                            'version': version
                        }
                        data['services'].append(service_info)
        
        return data
    
    def _parse_generic(self, output):
        """
        Generic parser for any scan type
        
        Returns:
            dict: Basic parsed information
        """
        data = {
            'host_status': 'unknown',
            'summary': ''
        }
        
        # Check if host is up
        if re.search(r'Host is up', output, re.IGNORECASE):
            data['host_status'] = 'up'
        elif re.search(r'Host seems down', output, re.IGNORECASE):
            data['host_status'] = 'down'
        
        # Extract summary line
        summary_match = re.search(r'Nmap done: (.+)', output)
        if summary_match:
            data['summary'] = summary_match.group(1)
        
        return data
    
    def parse_multiple_results(self, scan_results):
        """
        Parse multiple scan results
        
        Args:
            scan_results (list): List of scan result dictionaries
            
        Returns:
            list: List of parsed results
        """
        parsed_results = []
        
        for result in scan_results:
            parsed = self.parse_scan_result(result)
            parsed_results.append(parsed)
        
        return parsed_results
    
    def generate_summary(self, parsed_results):
        """
        Generate a high-level summary from parsed results
        
        Args:
            parsed_results (list): List of parsed scan results
            
        Returns:
            dict: Summary statistics
        """
        summary = {
            'total_scans': len(parsed_results),
            'successful_scans': 0,
            'failed_scans': 0,
            'hosts_up': 0,
            'hosts_down': 0,
            'total_open_ports': 0,
            'unique_services': set(),
            'targets_scanned': set()
        }
        
        for result in parsed_results:
            summary['targets_scanned'].add(result.get('target', 'Unknown'))
            
            if result.get('success', False):
                summary['successful_scans'] += 1
            else:
                summary['failed_scans'] += 1
            
            if result.get('host_status') == 'up':
                summary['hosts_up'] += 1
            elif result.get('host_status') == 'down':
                summary['hosts_down'] += 1
            
            # Count open ports
            for port in result.get('ports', []):
                if port.get('state') == 'open':
                    summary['total_open_ports'] += 1
            
            # Collect unique services
            for service in result.get('services', []):
                summary['unique_services'].add(service.get('service', 'unknown'))
        
        # Convert set to list for JSON serialization
        summary['unique_services'] = list(summary['unique_services'])
        summary['targets_scanned'] = list(summary['targets_scanned'])
        
        return summary
    
    def format_parsed_result(self, parsed_result):
        """
        Format a parsed result for display
        
        Args:
            parsed_result (dict): Parsed scan result
            
        Returns:
            str: Formatted string
        """
        lines = []
        lines.append("=" * 70)
        lines.append(f"Target: {parsed_result.get('target', 'Unknown')}")
        lines.append(f"Scan Type: {parsed_result.get('scan_name', 'Unknown')}")
        lines.append(f"Timestamp: {parsed_result.get('timestamp', 'Unknown')}")
        lines.append(f"Host Status: {parsed_result.get('host_status', 'Unknown').upper()}")
        lines.append("-" * 70)
        
        # Security context
        if parsed_result.get('security_context'):
            lines.append(f"Security Purpose: {parsed_result['security_context']}")
            lines.append("-" * 70)
        
        # Display ports
        ports = parsed_result.get('ports', [])
        if ports:
            lines.append(f"\nOpen Ports Found: {len([p for p in ports if p.get('state') == 'open'])}")
            lines.append(f"{'PORT':<10} {'PROTOCOL':<10} {'STATE':<10} {'SERVICE':<15} {'VERSION'}")
            for port in ports:
                if port.get('state') == 'open':
                    version = port.get('version', '')
                    lines.append(
                        f"{port.get('port', 'N/A'):<10} "
                        f"{port.get('protocol', 'N/A'):<10} "
                        f"{port.get('state', 'N/A'):<10} "
                        f"{port.get('service', 'N/A'):<15} "
                        f"{version}"
                    )
        
        # Display services
        services = parsed_result.get('services', [])
        if services:
            lines.append(f"\nServices Detected: {len(services)}")
            for service in services:
                lines.append(f"  - {service.get('service', 'Unknown')} on port {service.get('port', 'N/A')}")
                if service.get('version'):
                    lines.append(f"    Version: {service['version']}")
        
        # Warnings
        warnings = parsed_result.get('warnings', [])
        if warnings:
            lines.append("\nWarnings:")
            for warning in warnings:
                lines.append(f"  ! {warning}")
        
        lines.append("=" * 70)
        
        return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    # Test with sample Nmap output
    sample_output = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.068s latency).
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp  open  http    Apache httpd 2.4.7 ((Ubuntu))
443/tcp open  https   Apache httpd 2.4.7 ((Ubuntu))

Service detection performed. Please report any incorrect results.
Nmap done: 1 IP address (1 host up) scanned in 8.23 seconds
"""
    
    sample_result = {
        'target': 'scanme.nmap.org',
        'scan_type': 'service_version',
        'scan_name': 'Service Version Detection',
        'timestamp': '2025-12-06T10:30:00',
        'command': 'nmap -sV -v -Pn scanme.nmap.org',
        'security_context': 'Identifies specific software versions',
        'success': True,
        'output': sample_output
    }
    
    parser = OutputParser()
    parsed = parser.parse_scan_result(sample_result)
    
    print(parser.format_parsed_result(parsed))
