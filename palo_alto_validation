"""
Palo Alto Firewall Rule Validation Module
=========================================
This module provides validation for firewall rules before they're added to CSV.
Ensures all values are valid for Palo Alto Networks firewalls.
"""

import re
from typing import Dict, List, Tuple, Optional


class PaloAltoValidator:
    """Validator for Palo Alto firewall rule parameters."""
    
    # Valid actions for Palo Alto firewall rules
    VALID_ACTIONS = {
        'allow': 'Permit the traffic',
        'deny': 'Silently drop the traffic',
        'drop': 'Drop with TCP reset',
        'reset-client': 'Send TCP reset to client only',
        'reset-server': 'Send TCP reset to server only',
        'reset-both': 'Send TCP reset to both sides'
    }
    
    # Common Palo Alto App-IDs (protocols/applications)
    # This is a subset - Palo Alto has 3000+ applications in Applipedia
    COMMON_APPLICATIONS = {
        # Network protocols
        'tcp', 'udp', 'icmp', 'icmp6', 'sctp', 'gre', 'esp', 'ah',
        
        # Common applications
        'ssh', 'ssl', 'http', 'https', 'ftp', 'ftps', 'telnet', 'dns',
        'dhcp', 'ntp', 'snmp', 'smtp', 'pop3', 'imap',
        
        # Web and browsing
        'web-browsing', 'ssl-browsing',
        
        # Remote access
        'ms-rdp', 'vnc', 'teamviewer', 'citrix', 'vmware-view',
        
        # File sharing
        'smb', 'nfs', 'ftp-base',
        
        # Database
        'mysql', 'postgresql', 'mssql-db', 'oracle',
        
        # Messaging
        'ms-teams', 'slack', 'zoom', 'webex',
        
        # Special keywords
        'any', 'application-default',
        
        # Office/Business
        'office365', 'sharepoint', 'onedrive', 'google-drive',
        
        # VPN/Tunneling
        'ipsec', 'openvpn', 'wireguard',
        
        # Streaming
        'youtube', 'netflix', 'spotify',
        
        # Social media
        'facebook', 'twitter', 'instagram', 'linkedin'
    }
    
    # Valid protocols for service definition
    VALID_SERVICE_PROTOCOLS = {'tcp', 'udp', 'icmp'}
    
    # Port range
    MIN_PORT = 1
    MAX_PORT = 65535
    
    # IP address patterns
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    CIDR_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
    
    @classmethod
    def validate_action(cls, action: str) -> Tuple[bool, Optional[str]]:
        """
        Validate the action parameter.
        
        Args:
            action: The action to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        action_lower = action.lower().strip()
        
        if action_lower not in cls.VALID_ACTIONS:
            valid_options = '\n'.join([
                f"  • {act}: {desc}" 
                for act, desc in cls.VALID_ACTIONS.items()
            ])
            error = (
                f"❌ Invalid action '{action}'.\n\n"
                f"Valid actions for Palo Alto firewalls:\n{valid_options}"
            )
            return False, error
        
        return True, None
    
    @classmethod
    def validate_protocol(cls, protocol: str) -> Tuple[bool, Optional[str]]:
        """
        Validate the protocol/application parameter.
        
        Args:
            protocol: The protocol or App-ID to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        protocol_lower = protocol.lower().strip()
        
        # Allow 'any' as a valid option
        if protocol_lower == 'any':
            return True, None
        
        # Check if it's a common application
        if protocol_lower in cls.COMMON_APPLICATIONS:
            return True, None
        
        # If not in common list, provide a warning but allow it
        # (Palo Alto has 3000+ applications, we can't list them all)
        warning = (
            f"⚠️  Protocol/Application '{protocol}' is not in the common list.\n"
            f"   If this is a valid Palo Alto App-ID, it will work.\n"
            f"   Verify at: https://applipedia.paloaltonetworks.com/\n\n"
            f"Common applications include:\n"
            f"  • Network: tcp, udp, icmp, ssh, ssl, http, https, dns\n"
            f"  • Remote Access: ms-rdp, vnc, teamviewer, citrix\n"
            f"  • Web: web-browsing, ssl-browsing\n"
            f"  • Collaboration: ms-teams, slack, zoom, webex\n"
            f"  • Or use 'any' to match all applications"
        )
        return True, warning  # Allow but warn
    
    @classmethod
    def validate_port(cls, port: str) -> Tuple[bool, Optional[str]]:
        """
        Validate the port parameter.
        
        Args:
            port: The port to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        port_lower = port.lower().strip()
        
        # Allow special keywords
        if port_lower in ['any', 'application-default']:
            return True, None
        
        # Check if it's a valid port number
        try:
            port_num = int(port)
            if cls.MIN_PORT <= port_num <= cls.MAX_PORT:
                return True, None
            else:
                error = (
                    f"❌ Invalid port '{port}'.\n\n"
                    f"Port must be between {cls.MIN_PORT} and {cls.MAX_PORT}, "
                    f"or use:\n"
                    f"  • 'any' - Match any port\n"
                    f"  • 'application-default' - Use the application's default port"
                )
                return False, error
        except ValueError:
            # Check if it's a port range (e.g., "8000-8080")
            if '-' in port:
                try:
                    start, end = port.split('-')
                    start_num = int(start.strip())
                    end_num = int(end.strip())
                    
                    if cls.MIN_PORT <= start_num <= cls.MAX_PORT and \
                       cls.MIN_PORT <= end_num <= cls.MAX_PORT and \
                       start_num < end_num:
                        return True, None
                except ValueError:
                    pass
            
            error = (
                f"❌ Invalid port '{port}'.\n\n"
                f"Valid port formats:\n"
                f"  • Single port: 1-65535 (e.g., '80', '443')\n"
                f"  • Port range: '8000-8080'\n"
                f"  • 'any' - Match any port\n"
                f"  • 'application-default' - Use app's default port"
            )
            return False, error
    
    @classmethod
    def validate_ip_address(cls, ip: str, field_name: str = "IP") -> Tuple[bool, Optional[str]]:
        """
        Validate an IP address parameter.
        
        Args:
            ip: The IP address to validate
            field_name: Name of the field for error messages
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        ip_lower = ip.lower().strip()
        
        # Allow 'any' keyword
        if ip_lower == 'any':
            return True, None
        
        # Check for valid IP address format
        if cls.IP_PATTERN.match(ip):
            # Validate each octet is 0-255
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return True, None
        
        # Check for CIDR notation
        if cls.CIDR_PATTERN.match(ip):
            ip_part, prefix = ip.split('/')
            octets = ip_part.split('.')
            prefix_len = int(prefix)
            
            if all(0 <= int(octet) <= 255 for octet in octets) and 0 <= prefix_len <= 32:
                return True, None
        
        error = (
            f"❌ Invalid {field_name} '{ip}'.\n\n"
            f"Valid formats:\n"
            f"  • Single IP: 10.0.0.1\n"
            f"  • CIDR notation: 10.0.0.0/24\n"
            f"  • 'any' - Match any address"
        )
        return False, error
    
    @classmethod
    def validate_rule_name(cls, name: str) -> Tuple[bool, Optional[str]]:
        """
        Validate the rule name.
        
        Args:
            name: The rule name to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        name = name.strip()
        
        # Check length (Palo Alto limit is 63 characters)
        if len(name) == 0:
            return False, "❌ Rule name cannot be empty."
        
        if len(name) > 63:
            return False, (
                f"❌ Rule name '{name}' is too long ({len(name)} characters).\n"
                f"Maximum length is 63 characters."
            )
        
        # Check for invalid characters (Palo Alto allows alphanumeric, dash, underscore)
        if not re.match(r'^[a-zA-Z0-9_-]+$', name):
            return False, (
                f"❌ Rule name '{name}' contains invalid characters.\n"
                f"Rule names can only contain:\n"
                f"  • Letters (a-z, A-Z)\n"
                f"  • Numbers (0-9)\n"
                f"  • Hyphens (-)\n"
                f"  • Underscores (_)"
            )
        
        return True, None
    
    @classmethod
    def validate_description(cls, description: str) -> Tuple[bool, Optional[str]]:
        """
        Validate the description.
        
        Args:
            description: The description to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(description.strip()) == 0:
            return False, "❌ Description cannot be empty."
        
        if len(description) > 1024:
            return False, (
                f"❌ Description is too long ({len(description)} characters).\n"
                f"Maximum length is 1024 characters."
            )
        
        return True, None
    
    @classmethod
    def validate_all(cls, rule_data: Dict[str, str]) -> Tuple[bool, List[str]]:
        """
        Validate all fields in a rule.
        
        Args:
            rule_data: Dictionary containing rule parameters
            
        Returns:
            Tuple of (all_valid, list_of_messages)
        """
        messages = []
        all_valid = True
        
        # Validate rule name
        if 'rule_name' in rule_data:
            valid, msg = cls.validate_rule_name(rule_data['rule_name'])
            if not valid:
                all_valid = False
                messages.append(msg)
        
        # Validate action
        if 'action' in rule_data:
            valid, msg = cls.validate_action(rule_data['action'])
            if not valid:
                all_valid = False
                messages.append(msg)
            elif msg:  # Warning message
                messages.append(msg)
        
        # Validate protocol
        if 'protocol' in rule_data:
            valid, msg = cls.validate_protocol(rule_data['protocol'])
            if not valid:
                all_valid = False
                messages.append(msg)
            elif msg:  # Warning message
                messages.append(msg)
        
        # Validate port
        if 'port' in rule_data:
            valid, msg = cls.validate_port(rule_data['port'])
            if not valid:
                all_valid = False
                messages.append(msg)
        
        # Validate source IP
        if 'source_ip' in rule_data:
            valid, msg = cls.validate_ip_address(rule_data['source_ip'], "source IP")
            if not valid:
                all_valid = False
                messages.append(msg)
        
        # Validate destination IP
        if 'destination_ip' in rule_data:
            valid, msg = cls.validate_ip_address(rule_data['destination_ip'], "destination IP")
            if not valid:
                all_valid = False
                messages.append(msg)
        
        # Validate description
        if 'description' in rule_data:
            valid, msg = cls.validate_description(rule_data['description'])
            if not valid:
                all_valid = False
                messages.append(msg)
        
        return all_valid, messages


# Example usage:
if __name__ == "__main__":
    validator = PaloAltoValidator()
    
    # Test cases
    test_rule = {
        'rule_name': 'test-rule-001',
        'action': 'allow',
        'protocol': 'ssh',
        'port': '22',
        'source_ip': '10.0.0.0/24',
        'destination_ip': '192.168.1.1',
        'description': 'Test SSH rule'
    }
    
    valid, messages = validator.validate_all(test_rule)
    
    if valid:
        print("✅ All validations passed!")
    else:
        print("❌ Validation errors:")
        for msg in messages:
            print(f"\n{msg}")
    
    if messages and valid:  # Show warnings
        print("\n⚠️  Warnings:")
        for msg in messages:
            print(f"\n{msg}")