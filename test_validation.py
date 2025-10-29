#!/usr/bin/env python3
"""
Test script for Palo Alto Firewall Validation
==============================================
Run this to see how the validation works before integrating into MCP server.
"""

from palo_alto_validation import PaloAltoValidator

def print_separator():
    print("\n" + "="*80 + "\n")

def test_rule(test_name, rule_data):
    """Test a rule and print results."""
    print(f"🧪 TEST: {test_name}")
    print("-" * 80)
    print("Input:")
    for key, value in rule_data.items():
        print(f"  {key}: {value}")
    
    print("\nValidating...")
    is_valid, messages = PaloAltoValidator.validate_all(rule_data)
    
    if is_valid and not messages:
        print("\n✅ ALL VALIDATIONS PASSED! Rule is ready to be added.")
    elif is_valid and messages:
        print("\n✅ Validation passed with warnings:")
        for msg in messages:
            print(f"\n{msg}")
    else:
        print("\n❌ VALIDATION FAILED:")
        for msg in messages:
            print(f"\n{msg}")
    
    print_separator()

if __name__ == "__main__":
    print("="*80)
    print("PALO ALTO FIREWALL RULE VALIDATION TEST SUITE")
    print("="*80)
    
    # Test 1: Valid rule
    test_rule(
        "Valid SSH Rule",
        {
            'rule_name': 'allow-ssh-admin',
            'action': 'allow',
            'protocol': 'ssh',
            'port': '22',
            'source_ip': '10.0.0.0/24',
            'destination_ip': '192.168.1.100',
            'description': 'Allow SSH from admin network to server'
        }
    )
    
    # Test 2: Invalid action
    test_rule(
        "Invalid Action (should FAIL)",
        {
            'rule_name': 'block-traffic',
            'action': 'block',  # Invalid - should be 'deny' or 'drop'
            'protocol': 'tcp',
            'port': '80',
            'source_ip': '10.0.0.1',
            'destination_ip': 'any',
            'description': 'Block HTTP traffic'
        }
    )
    
    # Test 3: Invalid port
    test_rule(
        "Invalid Port (should FAIL)",
        {
            'rule_name': 'allow-web',
            'action': 'allow',
            'protocol': 'web-browsing',
            'port': '99999',  # Invalid - out of range
            'source_ip': 'any',
            'destination_ip': '192.168.1.1',
            'description': 'Allow web browsing'
        }
    )
    
    # Test 4: Invalid IP address
    test_rule(
        "Invalid IP Address (should FAIL)",
        {
            'rule_name': 'deny-invalid',
            'action': 'deny',
            'protocol': 'any',
            'port': 'any',
            'source_ip': '999.999.999.999',  # Invalid IP
            'destination_ip': '10.0.0.1',
            'description': 'Test invalid IP'
        }
    )
    
    # Test 5: Invalid rule name
    test_rule(
        "Invalid Rule Name (should FAIL)",
        {
            'rule_name': 'allow ssh from admin!!!',  # Invalid - spaces and special chars
            'action': 'allow',
            'protocol': 'ssh',
            'port': '22',
            'source_ip': '10.0.0.1',
            'destination_ip': '192.168.1.1',
            'description': 'SSH access'
        }
    )
    
    # Test 6: Uncommon application (should WARN)
    test_rule(
        "Uncommon Application (should WARN)",
        {
            'rule_name': 'allow-custom-app',
            'action': 'allow',
            'protocol': 'custom-internal-app',  # Not in common list
            'port': 'application-default',
            'source_ip': '10.0.0.0/24',
            'destination_ip': '172.16.0.1',
            'description': 'Allow custom internal application'
        }
    )
    
    # Test 7: Port range
    test_rule(
        "Valid Port Range",
        {
            'rule_name': 'allow-port-range',
            'action': 'allow',
            'protocol': 'tcp',
            'port': '8000-8999',  # Valid port range
            'source_ip': 'any',
            'destination_ip': '10.0.0.10',
            'description': 'Allow port range for web services'
        }
    )
    
    # Test 8: CIDR notation
    test_rule(
        "Valid CIDR Notation",
        {
            'rule_name': 'allow-subnet',
            'action': 'allow',
            'protocol': 'any',
            'port': 'any',
            'source_ip': '192.168.0.0/16',  # CIDR notation
            'destination_ip': '10.0.0.0/8',  # CIDR notation
            'description': 'Allow traffic between subnets'
        }
    )
    
    # Test 9: Multiple errors
    test_rule(
        "Multiple Validation Errors (should FAIL with multiple messages)",
        {
            'rule_name': 'bad rule name!!!',  # Invalid name
            'action': 'permit',  # Invalid action
            'protocol': 'tcp',
            'port': '70000',  # Invalid port
            'source_ip': '300.400.500.600',  # Invalid IP
            'destination_ip': 'any',
            'description': ''  # Empty description
        }
    )
    
    # Test 10: Real-world rule
    test_rule(
        "Real-World Rule - Allow MS Teams",
        {
            'rule_name': 'allow-ms-teams-office',
            'action': 'allow',
            'protocol': 'ms-teams',
            'port': 'application-default',
            'source_ip': '10.0.0.0/8',
            'destination_ip': 'any',
            'description': 'Allow Microsoft Teams for office network'
        }
    )
    
    print("\n" + "="*80)
    print("TEST SUITE COMPLETE")
    print("="*80)
    print("\n📚 Summary:")
    print("  • Tests 1, 7, 8, 10: Should PASS")
    print("  • Test 6: Should PASS with WARNING")
    print("  • Tests 2, 3, 4, 5, 9: Should FAIL with helpful error messages")
    print("\n💡 The validation provides helpful, specific error messages")
    print("   that show exactly what's wrong and what the valid options are.")
    print("\n🚀 Ready to integrate into your MCP server!")
    print("="*80 + "\n")
