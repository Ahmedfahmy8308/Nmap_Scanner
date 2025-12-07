"""
Input Handler Module
Handles user input and target specification for network assessment
"""

import re
import ipaddress
import os


class InputHandler:
    """
    Manages target input from files or console
    Validates IP addresses and CIDR notation
    """
    
    def __init__(self):
        self.targets = []
    
    def read_from_file(self, filepath):
        """
        Read targets from a text file
        Expected format: One target per line (IP address or CIDR notation)
        
        Args:
            filepath (str): Path to input file
            
        Returns:
            list: List of valid targets
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Input file not found: {filepath}")
        
        targets = []
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Validate and add target
                if self.validate_target(line):
                    targets.append(line)
                else:
                    print(f"Warning: Invalid target on line {line_num}: {line}")
        
        self.targets = targets
        return targets
    
    def read_from_console(self):
        """
        Read targets interactively from console
        
        Returns:
            list: List of valid targets
        """
        print("\n=== Target Input ===")
        print("Enter IP addresses or CIDR notation (one per line)")
        print("Examples: 192.168.1.1, 10.0.0.0/24, scanme.nmap.org")
        print("Type 'done' when finished\n")
        
        targets = []
        while True:
            target = input("Target: ").strip()
            
            if target.lower() == 'done':
                break
            
            if not target:
                continue
            
            if self.validate_target(target):
                targets.append(target)
                print(f"✓ Added: {target}")
            else:
                print(f"✗ Invalid target: {target}")
        
        self.targets = targets
        return targets
    
    def validate_target(self, target):
        """
        Validate if target is a valid IP, domain, or CIDR notation
        
        Args:
            target (str): Target to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Check for CIDR notation
        if '/' in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                return False
        
        # Check for IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Check for domain name (basic validation)
        # Allows letters, numbers, hyphens, and dots
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
        if re.match(domain_pattern, target):
            return True
        
        return False
    
    def expand_cidr(self, cidr):
        """
        Expand CIDR notation to list of individual IPs (for small networks only)
        
        Args:
            cidr (str): CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            list: List of IP addresses (limited to first 256 for safety)
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # Limit expansion to prevent overwhelming scans
            hosts = list(network.hosts())[:256]
            return [str(ip) for ip in hosts]
        except ValueError:
            return []
    
    def get_targets(self):
        """
        Get the list of targets
        
        Returns:
            list: Current list of targets
        """
        return self.targets
    
    def display_targets(self):
        """
        Display all targets in a formatted manner
        """
        if not self.targets:
            print("No targets specified.")
            return
        
        print(f"\n=== Targets ({len(self.targets)} total) ===")
        for idx, target in enumerate(self.targets, 1):
            print(f"{idx}. {target}")
        print()


# Example usage and testing
if __name__ == "__main__":
    handler = InputHandler()
    
    # Test validation
    test_targets = [
        "192.168.1.1",           # Valid IP
        "10.0.0.0/24",          # Valid CIDR
        "scanme.nmap.org",      # Valid domain
        "999.999.999.999",      # Invalid IP
        "invalid..domain",      # Invalid domain
    ]
    
    print("=== Testing Target Validation ===")
    for target in test_targets:
        valid = handler.validate_target(target)
        status = "✓ Valid" if valid else "✗ Invalid"
        print(f"{status}: {target}")
