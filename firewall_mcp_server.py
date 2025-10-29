from fastmcp import FastMCP
import pandas as pd
import os
from git import Repo
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============= CONFIGURATION =============
BASE_DIR = "/home/nabib/terraform-csv-firewall"
CSV_FILE = os.path.join(BASE_DIR, "rules.csv")
REPO_PATH = BASE_DIR

# Firewall connection - uses API key
FIREWALL_IP = "192.168.0.200"
API_KEY = "LUFRPT1wOU12bXpFZG9YZ2FBV1VRWFpWRU11OEltYzQ9ZytqWjRUUSt4bnhsbVY2VEtGbTIvSTV0QnVEKzErdGJsV3JscEcxOXk4NUhzRzFTcUZlcHVYTjNHSm5zWnBnMw=="  # Your actual API key from terraform.tfvars

# Initialize MCP
mcp = FastMCP("Palo Alto Firewall Manager")

# Connect to firewall
# Firewall connection - using direct API
FIREWALL_CONNECTED = True  # We'll check connectivity in each function
API_BASE = f"https://{FIREWALL_IP}/restapi/v10.2"


# ============= CSV OPERATIONS =============

@mcp.tool()
def list_csv_rules() -> str:
    """
    Show all firewall rules defined in the CSV file (your infrastructure as code).
    """
    try:
        if not os.path.exists(CSV_PATH):
            return f"❌ CSV file not found: {CSV_PATH}"
        
        df = pd.read_csv(CSV_PATH)
        
        if df.empty:
            return "CSV is empty - no rules defined"
        
        result = f"📋 Rules in CSV ({len(df)} total):\n\n"
        for idx, row in df.iterrows():
            result += f"{idx + 1}. {row['rule_name']}: {row['source_ip']} → {row['destination_ip']}:{row['port']} ({row['action']})\n"
            result += f"   Protocol: {row['protocol']}, Description: {row['description']}\n\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error reading CSV: {str(e)}"

@mcp.tool()
def search_csv_rule(search_term: str) -> str:
    """
    Search for rules in CSV by name or description.
    """
    try:
        df = pd.read_csv(CSV_PATH)
        
        # Search in rule_name and description columns
        mask = df['rule_name'].str.contains(search_term, case=False, na=False) | \
               df['description'].str.contains(search_term, case=False, na=False)
        matches = df[mask]
        
        if matches.empty:
            return f"No rules found matching '{search_term}'"
        
        result = f"🔍 Found {len(matches)} rule(s) matching '{search_term}':\n\n"
        for idx, row in matches.iterrows():
            result += f"• {row['rule_name']}: {row['source_ip']} → {row['destination_ip']}:{row['port']}\n"
            result += f"  {row['description']}\n\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error searching: {str(e)}"

@mcp.tool()
def add_rule_to_csv(rule_name: str, source_ip: str, destination_ip: str, 
                    port: str, protocol: str, action: str, description: str) -> str:
    """
    Add a new firewall rule to the CSV file.
    This does NOT deploy yet - you need to commit and push to trigger GitHub Actions.
    """
    try:
        df = pd.read_csv(CSV_PATH)
        
        # Check for duplicate names
        if rule_name in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' already exists in CSV"
        
        # Create new rule
        new_rule = pd.DataFrame([{
            'rule_name': rule_name,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'port': port,
            'protocol': protocol,
            'action': action,
            'description': description
        }])
        
        # Add to dataframe
        df = pd.concat([df, new_rule], ignore_index=True)
        
        # Save
        df.to_csv(CSV_PATH, index=False)
        
        return f"✅ Rule '{rule_name}' added to CSV!\n\n⚠️ Remember: You need to commit and push to deploy this rule to the firewall."
        
    except Exception as e:
        return f"❌ Error adding rule: {str(e)}"

@mcp.tool()
def delete_rule_from_csv(rule_name: str) -> str:
    """
    Delete a rule from the CSV file by name.
    """
    try:
        df = pd.read_csv(CSV_PATH)
        
        if rule_name not in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' not found in CSV"
        
        # Remove the rule
        df = df[df['rule_name'] != rule_name]
        
        # Save
        df.to_csv(CSV_PATH, index=False)
        
        return f"✅ Rule '{rule_name}' deleted from CSV.\n\n⚠️ Remember to commit and push to remove from firewall."
        
    except Exception as e:
        return f"❌ Error deleting rule: {str(e)}"

@mcp.tool()
def edit_csv_rule(rule_name: str, source_ip: str = None, destination_ip: str = None,
                  port: str = None, protocol: str = None, action: str = None, 
                  description: str = None) -> str:
    """
    Edit an existing rule in CSV. Only provide the fields you want to change.
    """
    try:
        df = pd.read_csv(CSV_PATH)
        
        if rule_name not in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' not found in CSV"
        
        # Update the row
        idx = df[df['rule_name'] == rule_name].index[0]
        
        updates = {}
        if source_ip: 
            df.at[idx, 'source_ip'] = source_ip
            updates['source_ip'] = source_ip
        if destination_ip: 
            df.at[idx, 'destination_ip'] = destination_ip
            updates['destination_ip'] = destination_ip
        if port: 
            df.at[idx, 'port'] = port
            updates['port'] = port
        if protocol: 
            df.at[idx, 'protocol'] = protocol
            updates['protocol'] = protocol
        if action: 
            df.at[idx, 'action'] = action
            updates['action'] = action
        if description: 
            df.at[idx, 'description'] = description
            updates['description'] = description
        
        # Save
        df.to_csv(CSV_PATH, index=False)
        
        return f"✅ Rule '{rule_name}' updated in CSV.\nChanges: {updates}\n\n⚠️ Commit and push to deploy changes."
        
    except Exception as e:
        return f"❌ Error editing rule: {str(e)}"

# ============= FIREWALL OPERATIONS =============

@mcp.tool()
def list_firewall_rules() -> str:
    """
    Show all security rules currently active on the actual firewall.
    """
    try:
        # Use XML API to get security rules
        url = f"https://{FIREWALL_IP}/api/"
        
        params = {
            "type": "config",
            "action": "get",
            "xpath": "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules",
            "key": API_KEY
        }
        
        response = requests.get(url, params=params, verify=False, timeout=10)
        
        if response.status_code != 200:
            return f"❌ API Error: {response.status_code} - {response.text[:300]}"
        
        # Parse XML response
        import xml.etree.ElementTree as ET
        root = ET.fromstring(response.text)
        
        # Check response status
        status = root.get('status')
        if status != 'success':
            return f"❌ API returned status: {status}\nResponse: {response.text[:300]}"
        
        # Find all rules
        rules = root.findall('.//entry')
        
        if not rules:
            return "No rules found on firewall"
        
        result = f"🔥 Rules on Firewall ({len(rules)} total):\n\n"
        
        for idx, rule in enumerate(rules, 1):
            name = rule.get('name', 'Unknown')
            
            # Get source
            source_elem = rule.find('.//source')
            source = 'any'
            if source_elem is not None:
                source_members = [m.text for m in source_elem.findall('.//member')]
                source = ', '.join(source_members) if source_members else 'any'
            
            # Get destination
            dest_elem = rule.find('.//destination')
            dest = 'any'
            if dest_elem is not None:
                dest_members = [m.text for m in dest_elem.findall('.//member')]
                dest = ', '.join(dest_members) if dest_members else 'any'
            
            # Get action
            action_elem = rule.find('.//action')
            action = action_elem.text if action_elem is not None else 'unknown'
            
            result += f"{idx}. {name}\n"
            result += f"   Source: {source}\n"
            result += f"   Destination: {dest}\n"
            result += f"   Action: {action}\n\n"
        
        return result
        
    except requests.exceptions.ConnectionError:
        return "❌ Cannot connect to firewall. Check IP and network connectivity."
    except Exception as e:
        return f"❌ Error: {type(e).__name__}: {str(e)}"


@mcp.tool()
def get_firewall_rule_details(rule_name: str) -> str:
    """
    Get detailed information about a specific rule on the firewall.
    """
    if not FIREWALL_CONNECTED:
        return "❌ Not connected to firewall"
    
    try:
        rule = fw.find(rule_name, SecurityRule)
        
        if not rule:
            return f"❌ Rule '{rule_name}' not found on firewall"
        
        details = f"""
📋 Firewall Rule Details: {rule.name}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
From Zone: {rule.fromzone}
To Zone: {rule.tozone}
Source: {rule.source}
Destination: {rule.destination}
Application: {rule.application}
Service: {rule.service}
Action: {rule.action}
Description: {rule.description if rule.description else 'None'}
"""
        return details
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
def compare_csv_vs_firewall() -> str:
    """
    Compare rules in CSV vs rules on actual firewall to check sync status.
    """
    if not FIREWALL_CONNECTED:
        return "❌ Not connected to firewall"
    
    try:
        # Get CSV rules
        df = pd.read_csv(CSV_PATH)
        csv_rules = set(df['rule_name'].values)
        
        # Get firewall rules
        SecurityRule.refreshall(fw)
        fw_rules = SecurityRule.refreshall(fw)

        fw_rule_names = set([r.name for r in fw_rules])
        
        # Compare
        only_in_csv = csv_rules - fw_rule_names
        only_on_firewall = fw_rule_names - csv_rules
        in_both = csv_rules & fw_rule_names
        
        result = f"""
📊 CSV vs Firewall Comparison
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Synced (in both): {len(in_both)} rules
📝 Pending deployment (CSV only): {len(only_in_csv)} rules
🔥 On firewall only (not in code): {len(only_on_firewall)} rules
"""
        
        if only_in_csv:
            result += f"\n\n📝 Rules in CSV but NOT deployed:\n"
            for r in only_in_csv:
                result += f"  • {r}\n"
        
        if only_on_firewall:
            result += f"\n\n🔥 Rules on firewall but NOT in CSV:\n"
            for r in only_on_firewall:
                result += f"  • {r}\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error comparing: {str(e)}"

# ============= GIT OPERATIONS =============

@mcp.tool()
def show_pending_changes() -> str:
    """
    Show what changes have been made to CSV that haven't been committed yet.
    """
    try:
        repo = Repo(REPO_PATH)
        
        if not repo.is_dirty(untracked_files=True):
            return "✅ No pending changes - CSV is clean"
        
        # Check if CSV was modified
        changed_files = [item.a_path for item in repo.index.diff(None)]
        
        if CSV_PATH.lstrip('./') not in changed_files:
            return "No changes to rules.csv"
        
        diff = repo.git.diff(CSV_PATH)
        
        return f"📝 Pending changes to rules.csv:\n\n{diff}\n\n⚠️ Remember to commit and push to deploy!"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
def commit_and_push_changes(commit_message: str) -> str:
    """
    Commit changes to rules.csv and push to GitHub (triggers CI/CD pipeline).
    
    Args:
        commit_message: Description of the changes being committed
    """
    try:
        # Initialize repo object
        repo = Repo(REPO_PATH)
        
        # Check if there are changes to commit
        if not repo.is_dirty() and not repo.untracked_files:
            return "⚠️ No changes to commit. Working tree is clean."
        
        # Add rules.csv to staging
        repo.index.add(['rules.csv'])
        
        # Commit with the provided message
        commit = repo.index.commit(commit_message)
        
        # Push to remote
        origin = repo.remote(name='origin')
        push_info = origin.push()
        
        # Check if push was successful
        if push_info and push_info[0].flags & 1024:  # ERROR flag
            return f"❌ Push failed: {push_info[0].summary}"
        
        result = f"""✅ Changes committed and pushed!
📝 Commit: {commit.hexsha[:7]} - {commit_message}

🚀 GitHub Actions pipeline should now be running...
   Check: https://github.com/Starkiller283/terraform-csv-firewall/actions
"""
        
        return result
        
    except Exception as e:
        return f"❌ Error: {type(e).__name__}: {str(e)}\n\nTry committing manually:\n  git add rules.csv\n  git commit -m \"{commit_message}\"\n  git push origin main"


# ============= RUN SERVER =============

if __name__ == "__main__":
    print("🚀 Starting Palo Alto Firewall MCP Server...")
    mcp.run(transport="stdio")
