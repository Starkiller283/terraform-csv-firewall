"""
Firewall Manager - Web Application (Streamlit)
Multi-user web interface for managing Palo Alto firewall rules

To run: streamlit run firewall_web_app.py
Access at: http://localhost:8501
"""

import streamlit as st
import pandas as pd
import os
from git import Repo
from pathlib import Path
from datetime import datetime
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import StructuredTool
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from pydantic import BaseModel, Field
from langchain_core.tools import Tool
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from palo_alto_validation import PaloAltoValidator


# ============= CONFIGURATION =============
SCRIPT_DIR = Path(__file__).parent.absolute()
CSV_PATH = str(SCRIPT_DIR / "rules.csv")
FIREWALL_IP = "192.168.0.18"
API_KEY = "LUFRPT1wOU12bXpFZG9YZ2FBV1VRWFpWRU11OEltYzQ9ZytqWjRUUSt4bnhsbVY2VEtGbTIvSTV0QnVEKzErdGJsV3JscEcxOXk4NUhzRzFTcUZlcHVYTjNHSm5zWnBnMw=="

# Page config
st.set_page_config(
    page_title="Firewall Manager",
    page_icon="🔥",
    layout="wide"
)

def apply_dark_security_theme():
    """Apply dark cybersecurity theme with custom CSS"""
    st.markdown("""
    <style>
    /* ============= MAIN BACKGROUND ============= */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    
    /* ============= SIDEBAR ============= */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #161b22 0%, #0d1117 100%);
        border-right: 1px solid #30363d;
    }
    
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] {
        color: #c9d1d9;
    }
    
    /* ============= CHAT MESSAGES ============= */
    .stChatMessage {
        background-color: #161b22 !important;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    
    /* User messages - blue accent */
    [data-testid="stChatMessageContent"]:has(+ [data-testid="stChatMessageAvatar"]) {
        background: linear-gradient(135deg, #1f2937 0%, #161b22 100%);
        border-left: 3px solid #58a6ff;
    }
    
    /* ============= INPUT FIELDS ============= */
    .stTextInput > div > div > input,
    .stTextArea textarea {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px;
    }
    
    .stTextInput > div > div > input:focus,
    .stTextArea textarea:focus {
        border-color: #58a6ff !important;
        box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1) !important;
    }
    
    /* ============= BUTTONS ============= */
    .stButton > button {
        background: linear-gradient(135deg, #1f6feb 0%, #1158c7 100%);
        color: white;
        border: none;
        border-radius: 6px;
        padding: 0.5rem 1rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #388bfd 0%, #1f6feb 100%);
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(31, 111, 235, 0.3);
    }
    
    /* ============= METRICS/STATS ============= */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: 700;
        color: #58a6ff;
    }
    
    [data-testid="stMetricLabel"] {
        color: #8b949e;
    }
    
    /* ============= HEADERS ============= */
    h1, h2, h3 {
        color: #58a6ff !important;
        font-weight: 700;
    }
    
    h1 {
        text-shadow: 0 0 20px rgba(88, 166, 255, 0.3);
    }
    
    /* ============= TEXT ============= */
    p, span, div {
        color: #c9d1d9;
    }
    
    /* ============= CODE BLOCKS ============= */
    code {
        background-color: #161b22 !important;
        color: #79c0ff !important;
        padding: 0.2rem 0.4rem;
        border-radius: 3px;
        font-family: 'Fira Code', 'Courier New', monospace;
    }
    
    /* ============= CHAT INPUT ============= */
    .stChatInputContainer {
        background-color: #0d1117;
        border-top: 1px solid #30363d;
    }
    
    .stChatInput > div {
        background-color: #161b22 !important;
        border: 1px solid #30363d !important;
    }
    
    /* ============= SCROLLBAR ============= */
    ::-webkit-scrollbar {
        width: 10px;
        background-color: #0d1117;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #30363d 0%, #21262d 100%);
        border-radius: 5px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #484f58 0%, #30363d 100%);
    }
    
    /* ============= DIVIDERS ============= */
    hr {
        border-color: #30363d;
    }
    
    /* ============= SUCCESS/ERROR MESSAGES ============= */
    .stSuccess {
        background-color: #0d1117 !important;
        border-left: 4px solid #3fb950 !important;
        color: #3fb950 !important;
    }
    
    .stError {
        background-color: #0d1117 !important;
        border-left: 4px solid #f85149 !important;
        color: #f85149 !important;
    }
    
    .stWarning {
        background-color: #0d1117 !important;
        border-left: 4px solid #d29922 !important;
        color: #d29922 !important;
    }
    
    .stInfo {
        background-color: #0d1117 !important;
        border-left: 4px solid #58a6ff !important;
        color: #58a6ff !important;
    }
    
    /* ============= SPINNER ============= */
    .stSpinner > div {
        border-top-color: #58a6ff !important;
    }
    </style>
    """, unsafe_allow_html=True)
# ============= FUNCTIONS (Same as before) =============

def list_csv_rules() -> str:
    """Show all firewall rules in CSV"""
    try:
        if not os.path.exists(CSV_PATH):
            return f" CSV file not found: {CSV_PATH}"
        
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


def add_rule_to_csv(rule_name: str, source_ip: str, destination_ip: str,
                    port: str, protocol: str, action: str,
                    description: str) -> str:
    """Add a new rule to CSV with validation"""
    try:
        # Validate rule data first
        rule_data = {
            'rule_name': rule_name,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'port': port,
            'protocol': protocol,
            'action': action,
            'description': description
        }
        
        # Run validation
        is_valid, messages = PaloAltoValidator.validate_all(rule_data)
        
        if not is_valid:
            # Return validation errors
            error_msg = "❌ Validation failed:\n\n" + "\n\n".join(messages)
            return error_msg
        
        # Check for duplicate rule name
        df = pd.read_csv(CSV_PATH)
        if rule_name in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' already exists in CSV"
        
        # Add the rule
        new_rule = pd.DataFrame([rule_data])
        df = pd.concat([df, new_rule], ignore_index=True)
        df.to_csv(CSV_PATH, index=False)
        
        log_change(st.session_state.get('username', 'unknown'), 'ADD', rule_name)
        
        # Build success message with any warnings
        success_msg = f"✅ Rule '{rule_name}' added successfully!"
        if messages:
            success_msg += "\n\n⚠️ Warnings:\n" + "\n".join(messages)
        
        return success_msg
    except Exception as e:
        return f"❌ Error adding rule: {str(e)}"



def delete_rule_from_csv(rule_name: str) -> str:
    """Delete a rule from CSV"""
    try:
        df = pd.read_csv(CSV_PATH)
        
        if rule_name not in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' not found in CSV"
        
        df = df[df['rule_name'] != rule_name]
        df.to_csv(CSV_PATH, index=False)
        
        # Log the change
        log_change(st.session_state.get('username', 'unknown'), 'DELETE', rule_name)
        
        return f"✅ Rule '{rule_name}' deleted from CSV."
    except Exception as e:
        return f"❌ Error deleting rule: {str(e)}"


def list_firewall_rules() -> str:
    """Show rules on actual firewall"""
    try:
        url = f"https://{FIREWALL_IP}/api/"
        params = {
            "type": "config",
            "action": "get",
            "xpath": "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules",
            "key": API_KEY
        }
        
        response = requests.get(url, params=params, verify=False, timeout=10)
        
        if response.status_code != 200:
            return f"❌ API Error: {response.status_code}"
        
        import xml.etree.ElementTree as ET
        root = ET.fromstring(response.text)
        
        status = root.get('status')
        if status != 'success':
            return f"❌ API returned status: {status}"
        
        rules = root.findall('.//entry')
        
        if not rules:
            return "No rules found on firewall"
        
        result = f"🔥 Rules on Firewall ({len(rules)} total):\n\n"
        
        for idx, rule in enumerate(rules, 1):
            name = rule.get('name', 'Unknown')
            
            source_elem = rule.find('.//source')
            source = 'any'
            if source_elem is not None:
                source_members = [m.text for m in source_elem.findall('.//member')]
                source = ', '.join(source_members) if source_members else 'any'
            
            dest_elem = rule.find('.//destination')
            dest = 'any'
            if dest_elem is not None:
                dest_members = [m.text for m in dest_elem.findall('.//member')]
                dest = ', '.join(dest_members) if dest_members else 'any'
            
            action_elem = rule.find('.//action')
            action = action_elem.text if action_elem is not None else 'unknown'
            
            result += f"{idx}. {name}\n"
            result += f"   Source: {source}\n"
            result += f"   Destination: {dest}\n"
            result += f"   Action: {action}\n\n"
        
        return result
    except Exception as e:
        return f"❌ Error: {type(e).__name__}: {str(e)}"


def log_change(username: str, action: str, rule_name: str):
    """Log changes to audit file"""
    log_file = SCRIPT_DIR / "audit_log.csv"
    timestamp = datetime.now().isoformat()
    
    log_entry = pd.DataFrame([{
        'timestamp': timestamp,
        'username': username,
        'action': action,
        'rule_name': rule_name
    }])
    
    if log_file.exists():
        df = pd.read_csv(log_file)
        df = pd.concat([df, log_entry], ignore_index=True)
    else:
        df = log_entry
    
    df.to_csv(log_file, index=False)

def edit_rule_in_csv(rule_name: str, source_ip: str = None, destination_ip: str = None,
                     port: str = None, protocol: str = None, action: str = None,
                     description: str = None) -> str:
    """Edit an existing rule in CSV with validation"""
    try:
        df = pd.read_csv(CSV_PATH)
        if rule_name not in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' not found in CSV"
        
        # Build dict of fields to validate
        validation_data = {}
        updates = {}
        
        if source_ip:
            validation_data['source_ip'] = source_ip
            updates['source_ip'] = source_ip
        if destination_ip:
            validation_data['destination_ip'] = destination_ip
            updates['destination_ip'] = destination_ip
        if port:
            validation_data['port'] = port
            updates['port'] = port
        if protocol:
            validation_data['protocol'] = protocol
            updates['protocol'] = protocol
        if action:
            validation_data['action'] = action
            updates['action'] = action
        if description:
            validation_data['description'] = description
            updates['description'] = description
        
        # Validate only the fields being changed
        if validation_data:
            is_valid, messages = PaloAltoValidator.validate_all(validation_data)
            
            if not is_valid:
                error_msg = "❌ Validation failed:\n\n" + "\n\n".join(messages)
                return error_msg
        
        # Update the row
        idx = df[df['rule_name'] == rule_name].index[0]
        for field, value in updates.items():
            df.at[idx, field] = value
        
        df.to_csv(CSV_PATH, index=False)
        log_change(st.session_state.get('username', 'unknown'), 'EDIT', rule_name)
        
        # Build success message
        success_msg = f"✅ Rule '{rule_name}' updated.\nChanges: {updates}"
        if validation_data and messages:
            success_msg += "\n\n⚠️ Warnings:\n" + "\n".join(messages)
        
        return success_msg
    except Exception as e:
        return f"❌ Error editing rule: {str(e)}"



def reorder_rule(rule_name: str, new_position: int) -> str:
    """Move a rule to a different position (1-based index)"""
    try:
        df = pd.read_csv(CSV_PATH)
        if rule_name not in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' not found"
        
        # Get current position
        current_idx = df[df['rule_name'] == rule_name].index[0]
        
        # Convert to 0-based and validate
        new_idx = new_position - 1
        if new_idx < 0 or new_idx >= len(df):
            return f"❌ Position {new_position} is out of range (1-{len(df)})"
        
        # Reorder by moving the row
        rule_row = df.iloc[current_idx:current_idx+1]
        df = df.drop(current_idx).reset_index(drop=True)
        df = pd.concat([df.iloc[:new_idx], rule_row, df.iloc[new_idx:]]).reset_index(drop=True)
        
        df.to_csv(CSV_PATH, index=False)
        log_change(st.session_state.get('username', 'unknown'), 'REORDER', rule_name)
        
        return f"✅ Rule '{rule_name}' moved to position {new_position}"
    except Exception as e:
        return f"❌ Error reordering: {str(e)}"
    

def show_pending_changes() -> str:
    """Show uncommitted changes to CSV"""
    try:
        repo = Repo(SCRIPT_DIR)
        if not repo.is_dirty(untracked_files=True):
            return " No pending changes - CSV is clean"
        
        changed_files = [item.a_path for item in repo.index.diff(None)]
        if 'rules.csv' not in changed_files:
            return "No changes to rules.csv"
        
        diff = repo.git.diff(CSV_PATH)
        return f" Pending changes:\n\n{diff}\n\n⚠️ Commit and push to deploy!"
    except Exception as e:
        return f" Error: {str(e)}"

def commit_and_push_changes(commit_message: str) -> str:
    """Commit CSV changes and push to GitHub"""
    try:
        repo = Repo(SCRIPT_DIR)
        
        if not repo.is_dirty() and not repo.untracked_files:
            return "✅ No changes to commit"
        
        # Stage and commit
        repo.index.add(['rules.csv'])
        commit = repo.index.commit(commit_message)
        
        # Push
        origin = repo.remote(name='origin')
        push_info = origin.push()
        
        if push_info and push_info[0].flags & 1024:
            return f"❌ Push failed: {push_info[0].summary}"
        
        result = f"""✅ Changes deployed!
        
Commit: {commit.hexsha[:7]} - {commit_message}
GitHub Actions running...
"""
        log_change(st.session_state.get('username', 'unknown'), 'COMMIT', commit_message)
        return result
    except Exception as e:
        return f"❌ Error: {str(e)}"


def validate_rule_syntax(rule_name: str = None, source_ip: str = None, 
                        destination_ip: str = None, port: str = None,
                        protocol: str = None, action: str = None) -> str:
    """Validate rule parameters without saving"""
    rule_data = {}
    if rule_name:
        rule_data['rule_name'] = rule_name
    if source_ip:
        rule_data['source_ip'] = source_ip
    if destination_ip:
        rule_data['destination_ip'] = destination_ip
    if port:
        rule_data['port'] = port
    if protocol:
        rule_data['protocol'] = protocol
    if action:
        rule_data['action'] = action
    
    is_valid, messages = PaloAltoValidator.validate_all(rule_data)
    
    if is_valid and not messages:
        return " All parameters are valid!"
    elif is_valid and messages:
        return " Valid with warnings:\n\n" + "\n\n".join(messages)
    else:
        return " Validation errors:\n\n" + "\n\n".join(messages)
    

def get_last_rule() -> str:
    """Get the name of the last rule in CSV"""
    try:
        df = pd.read_csv(CSV_PATH)
        if df.empty:
            return " No rules in CSV"
        
        last_rule = df.iloc[-1]['rule_name']
        return f"The last rule is: {last_rule}"
    except Exception as e:
        return f" Error: {str(e)}"

def get_first_rule() -> str:
    """Get the name of the first rule in CSV"""
    try:
        df = pd.read_csv(CSV_PATH)
        if df.empty:
            return " No rules in CSV"
        
        first_rule = df.iloc[0]['rule_name']
        return f"The first rule is: {first_rule}"
    except Exception as e:
        return f" Error: {str(e)}"

def get_rule_at_position(position: int) -> str:
    """Get the name of a rule at a specific position (1-based)"""
    try:
        df = pd.read_csv(CSV_PATH)
        if df.empty:
            return " No rules in CSV"
        
        if position < 1 or position > len(df):
            return f" Position {position} out of range. There are {len(df)} rules."
        
        rule_name = df.iloc[position - 1]['rule_name']
        return f"Rule at position {position} is: {rule_name}"
    except Exception as e:
        return f" Error: {str(e)}"

def count_rules() -> str:
    """Count total number of rules"""
    try:
        df = pd.read_csv(CSV_PATH)
        total = len(df)
        allow = len(df[df['action'] == 'allow'])
        deny = len(df[df['action'] == 'deny'])
        return f"Total rules: {total}\n• Allow rules: {allow}\n• Deny rules: {deny}"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def find_rule_by_keyword(keyword: str) -> str:
    """Find rules containing a keyword"""
    try:
        df = pd.read_csv(CSV_PATH)
        mask = (df['rule_name'].str.contains(keyword, case=False, na=False) | 
                df['description'].str.contains(keyword, case=False, na=False))
        matches = df[mask]
        
        if matches.empty:
            return f"No rules found containing '{keyword}'"
        
        result = f"Found {len(matches)} rule(s) with '{keyword}':\n\n"
        for idx, row in matches.iterrows():
            result += f"• {row['rule_name']}: {row['description']}\n"
        return result
    except Exception as e:
        return f"❌ Error: {str(e)}"

def find_rule_by_keyword_wrapper(keyword: str) -> str:
    """Wrapper for find_rule_by_keyword"""
    return find_rule_by_keyword(str(keyword).strip())


def find_rules_by_ip(ip_address: str) -> str:
    """Find all rules involving a specific IP"""
    try:
        df = pd.read_csv(CSV_PATH)
        mask = (df['source_ip'].str.contains(ip_address, case=False, na=False) | 
                df['destination_ip'].str.contains(ip_address, case=False, na=False))
        matches = df[mask]
        
        if matches.empty:
            return f"No rules found for IP '{ip_address}'"
        
        result = f"Found {len(matches)} rule(s) involving {ip_address}:\n\n"
        for idx, row in matches.iterrows():
            result += f"• {row['rule_name']}: {row['source_ip']} → {row['destination_ip']}\n"
        return result
    except Exception as e:
        return f"❌ Error: {str(e)}"

def find_rules_by_ip_wrapper(ip_address: str) -> str:
    """Wrapper for find_rules_by_ip"""
    return find_rules_by_ip(str(ip_address).strip())


def find_rules_by_port(port: str) -> str:
    """Find all rules for a specific port"""
    try:
        df = pd.read_csv(CSV_PATH)
        matches = df[df['port'].astype(str) == str(port)]
        
        if matches.empty:
            return f"No rules found for port {port}"
        
        result = f"Found {len(matches)} rule(s) on port {port}:\n\n"
        for idx, row in matches.iterrows():
            result += f"• {row['rule_name']}: {row['action']} - {row['description']}\n"
        return result
    except Exception as e:
        return f"❌ Error: {str(e)}"

def get_allow_rules() -> str:
    """Get all 'allow' rules"""
    try:
        df = pd.read_csv(CSV_PATH)
        allows = df[df['action'] == 'allow']
        
        if allows.empty:
            return "No allow rules found"
        
        result = f"Allow rules ({len(allows)} total):\n\n"
        for idx, row in allows.iterrows():
            result += f"• {row['rule_name']}: {row['source_ip']} → {row['destination_ip']}:{row['port']}\n"
        return result
    except Exception as e:
        return f"❌ Error: {str(e)}"

def get_deny_rules() -> str:
    """Get all 'deny' rules"""
    try:
        df = pd.read_csv(CSV_PATH)
        denies = df[df['action'] == 'deny']
        
        if denies.empty:
            return "No deny rules found"
        
        result = f"Deny rules ({len(denies)} total):\n\n"
        for idx, row in denies.iterrows():
            result += f"• {row['rule_name']}: {row['source_ip']} → {row['destination_ip']}:{row['port']}\n"
        return result
    except Exception as e:
        return f"❌ Error: {str(e)}"

def get_rule_details(rule_name: str) -> str:
    """Get full details of a specific rule"""
    try:
        df = pd.read_csv(CSV_PATH)
        rule = df[df['rule_name'] == rule_name]
        
        if rule.empty:
            return f"Rule '{rule_name}' not found"
        
        r = rule.iloc[0]
        return f"""📋 Rule: {r['rule_name']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action: {r['action']}
Protocol: {r['protocol']}
Source: {r['source_ip']}
Destination: {r['destination_ip']}
Port: {r['port']}
Description: {r['description']}"""
    except Exception as e:
        return f"❌ Error: {str(e)}"

def delete_rules_containing(keyword: str) -> str:
    """Delete all rules with keyword in name/description"""
    try:
        df = pd.read_csv(CSV_PATH)
        mask = (df['rule_name'].str.contains(keyword, case=False, na=False) | 
                df['description'].str.contains(keyword, case=False, na=False))
        to_delete = df[mask]
        count = len(to_delete)
        
        if count == 0:
            return f"No rules found containing '{keyword}'"
        
        deleted_names = to_delete['rule_name'].tolist()
        df = df[~mask]
        df.to_csv(CSV_PATH, index=False)
        
        return f"✅ Deleted {count} rule(s): {', '.join(deleted_names)}"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def disable_rule(rule_name: str) -> str:
    """Disable a rule by adding 'DISABLED-' prefix"""
    try:
        df = pd.read_csv(CSV_PATH)
        if rule_name not in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' not found"
        
        idx = df[df['rule_name'] == rule_name].index[0]
        new_name = f"DISABLED-{rule_name}"
        df.at[idx, 'rule_name'] = new_name
        df.to_csv(CSV_PATH, index=False)
        log_change(st.session_state.get('username', 'unknown'), 'DISABLE', rule_name)
        
        return f"✅ Rule disabled (renamed to '{new_name}')"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def enable_rule(rule_name: str) -> str:
    """Enable a disabled rule"""
    try:
        df = pd.read_csv(CSV_PATH)
        disabled_name = f"DISABLED-{rule_name}" if not rule_name.startswith("DISABLED-") else rule_name
        
        if disabled_name not in df['rule_name'].values:
            return f"❌ Rule '{disabled_name}' not found"
        
        idx = df[df['rule_name'] == disabled_name].index[0]
        new_name = disabled_name.replace("DISABLED-", "")
        df.at[idx, 'rule_name'] = new_name
        df.to_csv(CSV_PATH, index=False)
        log_change(st.session_state.get('username', 'unknown'), 'ENABLE', rule_name)
        
        return f"✅ Rule enabled (renamed to '{new_name}')"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def duplicate_rule(rule_name: str, new_name: str) -> str:
    """Create a copy of an existing rule"""
    try:
        df = pd.read_csv(CSV_PATH)
        
        if rule_name not in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' not found"
        
        if new_name in df['rule_name'].values:
            return f"❌ Rule '{new_name}' already exists"
        
        original = df[df['rule_name'] == rule_name].iloc[0]
        new_rule = original.copy()
        new_rule['rule_name'] = new_name
        
        df = pd.concat([df, new_rule.to_frame().T], ignore_index=True)
        df.to_csv(CSV_PATH, index=False)
        log_change(st.session_state.get('username', 'unknown'), 'DUPLICATE', new_name)
        
        return f"✅ Rule '{rule_name}' duplicated as '{new_name}'"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def get_recent_rules(count: int = 5) -> str:
    """Get the N most recently added rules"""
    try:
        df = pd.read_csv(CSV_PATH)
        if len(df) == 0:
            return "No rules in CSV"
        
        count = min(count, len(df))
        recent = df.tail(count)
        
        result = f"Last {count} rule(s):\n\n"
        for idx, row in recent.iterrows():
            result += f"• {row['rule_name']}: {row['description']}\n"
        return result
    except Exception as e:
        return f"❌ Error: {str(e)}"

def check_rule_exists(rule_name: str) -> str:
    """Check if a rule exists"""
    try:
        df = pd.read_csv(CSV_PATH)
        exists = rule_name in df['rule_name'].values
        
        if exists:
            return f"✅ Rule '{rule_name}' exists"
        else:
            similar = df[df['rule_name'].str.contains(rule_name, case=False, na=False)]['rule_name'].tolist()
            if similar:
                return f"❌ Rule '{rule_name}' not found. Did you mean: {', '.join(similar[:3])}?"
            return f"❌ Rule '{rule_name}' not found"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def summarize_rules() -> str:
    """Get a high-level summary"""
    try:
        df = pd.read_csv(CSV_PATH)
        
        if df.empty:
            return "No rules in CSV"
        
        total = len(df)
        allows = len(df[df['action'] == 'allow'])
        denies = len(df[df['action'] == 'deny'])
        protocols = df['protocol'].value_counts().head(3)
        ports = df['port'].value_counts().head(3)
        
        result = f"""📊 Rules Summary
━━━━━━━━━━━━━━━━━━━━━━━━
Total Rules: {total}
• Allow: {allows}
• Deny: {denies}

Top Protocols:
"""
        for proto, count in protocols.items():
            result += f"• {proto}: {count}\n"
        
        result += f"\nTop Ports:\n"
        for port, count in ports.items():
            result += f"• {port}: {count}\n"
        
        return result
    except Exception as e:
        return f"❌ Error: {str(e)}"

def get_last_rule() -> str:
    """Get the name of the last rule"""
    try:
        df = pd.read_csv(CSV_PATH)
        if df.empty:
            return "❌ No rules in CSV"
        return f"The last rule is: {df.iloc[-1]['rule_name']}"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def get_first_rule() -> str:
    """Get the name of the first rule"""
    try:
        df = pd.read_csv(CSV_PATH)
        if df.empty:
            return "❌ No rules in CSV"
        return f"The first rule is: {df.iloc[0]['rule_name']}"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def get_rule_at_position(position: int) -> str:
    """Get rule name at position (1-based)"""
    try:
        df = pd.read_csv(CSV_PATH)
        if df.empty:
            return "❌ No rules in CSV"
        if position < 1 or position > len(df):
            return f"❌ Position {position} out of range. There are {len(df)} rules."
        return f"Rule at position {position} is: {df.iloc[position - 1]['rule_name']}"
    except Exception as e:
        return f"❌ Error: {str(e)}"
    
def get_rule_at_position_wrapper(position: int) -> str:
    """Wrapper to handle tool calling"""
    # Ensure position is an integer
    if isinstance(position, str):
        position = int(position)
    return get_rule_at_position(position)

def find_rules_by_port_wrapper(port: str) -> str:
    """Wrapper for find_rules_by_port"""
    port = str(port).strip()
    return find_rules_by_port(port)

def get_rule_details_wrapper(rule_name: str) -> str:
    """Wrapper for get_rule_details"""
    rule_name = str(rule_name).strip()
    return get_rule_details(rule_name)

def check_rule_exists_wrapper(rule_name: str) -> str:
    """Wrapper for check_rule_exists"""
    rule_name = str(rule_name).strip()
    return check_rule_exists(rule_name)

def delete_rules_containing_wrapper(keyword: str) -> str:
    """Wrapper for delete_rules_containing"""
    keyword = str(keyword).strip()
    return delete_rules_containing(keyword)

def disable_rule_wrapper(rule_name: str) -> str:
    """Wrapper for disable_rule"""
    rule_name = str(rule_name).strip()
    return disable_rule(rule_name)

def enable_rule_wrapper(rule_name: str) -> str:
    """Wrapper for enable_rule"""
    rule_name = str(rule_name).strip()
    return enable_rule(rule_name)

# ============= SMART HELPER FUNCTIONS =============

def normalize_action(action_text: str) -> str:
    """Convert various phrasings to standard actions"""
    action_lower = action_text.lower()
    
    if any(word in action_lower for word in ['allow', 'permit', 'let', 'enable', 'grant']):
        return 'allow'
    elif any(word in action_lower for word in ['deny', 'block', 'stop', 'prevent', 'reject']):
        return 'deny'
    
    return action_text

def detect_service_from_text(text: str) -> tuple:
    """Detect common services and return (protocol, port)"""
    text_lower = text.lower()
    
    service_map = {
        'ssh': ('tcp', '22'),
        'http': ('tcp', '80'),
        'https': ('tcp', '443'),
        'ssl': ('tcp', '443'),
        'dns': ('udp', '53'),
        'ftp': ('tcp', '21'),
        'mysql': ('tcp', '3306'),
        'database': ('tcp', '3306'),
        'rdp': ('tcp', '3389'),
    }
    
    for keyword, (proto, port) in service_map.items():
        if keyword in text_lower:
            return (proto, port)
    
    return (None, None)

def extract_ips_from_text(text: str) -> list:
    """Extract IP addresses from natural language"""
    import re
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
    return re.findall(ip_pattern, text)


# ============= LANGCHAIN TOOLS =============

class AddRuleInput(BaseModel):
    """Input schema for adding a rule"""
    rule_name: str = Field(description="Name for the firewall rule")
    source_ip: str = Field(description="Source IP address")
    destination_ip: str = Field(description="Destination IP address")
    port: str = Field(description="Port number")
    protocol: str = Field(description="Protocol (tcp/udp)")
    action: str = Field(description="Action (allow/deny)")
    description: str = Field(description="Rule description")


# Create tools
def list_csv_rules_wrapper(*args, **kwargs):
    """Wrapper to handle any extra arguments from LangChain"""
    return list_csv_rules()

list_csv_tool = Tool(
    name="list_csv_rules",
    func=list_csv_rules_wrapper,
    description="Show all firewall rules in the CSV file"
)

add_rule_tool = StructuredTool(
    name="add_rule_to_csv",
    func=add_rule_to_csv,
    description="Add a new firewall rule to CSV",
    args_schema=AddRuleInput
)

def delete_rule_wrapper(rule_name: str) -> str:
    """Wrapper to ensure proper string handling"""
    rule_name = str(rule_name).strip()
    return delete_rule_from_csv(rule_name)

# Add schema class (put this near your other schema classes around line 407)
class DeleteRuleInput(BaseModel):
    """Input schema for deleting a rule"""
    rule_name: str = Field(description="Exact name of the firewall rule to delete (case-sensitive)")

# Replace the tool definition
delete_rule_tool = StructuredTool(
    name="delete_rule_from_csv",
    func=delete_rule_wrapper,
    description="Delete a firewall rule from CSV by its exact name. Rule names are case-sensitive. List rules first to get the exact name.",
    args_schema=DeleteRuleInput
)

def list_firewall_rules_wrapper(*args, **kwargs):
    """Wrapper to handle any extra arguments from LangChain"""
    return list_firewall_rules()

list_firewall_tool = Tool(
    name="list_firewall_rules",
    func=list_firewall_rules_wrapper,
    description="Show rules on the actual firewall"
)

validate_tool = Tool(
    name="validate_rule_syntax",
    func=validate_rule_syntax,
    description="Validate firewall rule parameters before adding/editing"
)

class EditRuleInput(BaseModel):
    """Input schema for editing a rule"""
    rule_name: str = Field(description="Name of rule to edit")
    source_ip: str = Field(default=None, description="New source IP")
    destination_ip: str = Field(default=None, description="New destination IP")
    port: str = Field(default=None, description="New port")
    protocol: str = Field(default=None, description="New protocol")
    action: str = Field(default=None, description="New action")
    description: str = Field(default=None, description="New description")

edit_rule_tool = StructuredTool(
    name="edit_rule_in_csv",
    func=edit_rule_in_csv,
    description="Edit an existing firewall rule. Only provide fields to change.",
    args_schema=EditRuleInput
)

class ReorderRuleInput(BaseModel):
    """Input schema for reordering"""
    rule_name: str = Field(description="Name of rule to move")
    new_position: int = Field(description="New position (1-based)")

reorder_rule_tool = StructuredTool(
    name="reorder_rule",
    func=reorder_rule,
    description="Change the order of a firewall rule",
    args_schema=ReorderRuleInput
)

commit_tool = StructuredTool(
    name="commit_and_push",
    func=commit_and_push_changes,
    description="Commit CSV changes and push to GitHub to deploy",
    args_schema=type('CommitInput', (BaseModel,), {
        '__annotations__': {'commit_message': str},
        'commit_message': Field(description="Commit message describing changes")
    })
)

show_changes_tool = Tool(
    name="show_pending_changes",
    func=lambda *args, **kwargs: show_pending_changes(),
    description="Show uncommitted changes to rules CSV"
)

get_last_rule_tool = Tool(
    name="get_last_rule",
    func=lambda *args, **kwargs: get_last_rule(),
    description="Get the name of the last (bottom) rule in the CSV file. Use this when user says 'last rule' or 'bottom rule'."
)

get_first_rule_tool = Tool(
    name="get_first_rule", 
    func=lambda *args, **kwargs: get_first_rule(),
    description="Get the name of the first (top) rule in the CSV file. Use this when user says 'first rule' or 'top rule'."
)

class GetRulePositionInput(BaseModel):
    """Input schema for getting rule at position"""
    position: int = Field(description="Position number (1-based index) of the rule to get")

get_rule_position_tool = StructuredTool(
    name="get_rule_at_position",
    func=get_rule_at_position_wrapper,  # ← Using wrapper
    description="Get the name of a rule at a specific position number (1 = first, 2 = second, etc). Use when user refers to a numbered position like 'rule 3' or '3rd rule'.",
    args_schema=GetRulePositionInput
)

class DuplicateRuleInput(BaseModel):
    """Input schema for duplicating a rule"""
    rule_name: str = Field(description="Name of the rule to copy")
    new_name: str = Field(description="Name for the new duplicate rule")

class GetRecentInput(BaseModel):
    """Input schema for getting recent rules"""
    count: int = Field(default=5, description="Number of recent rules to show")

count_rules_tool = Tool(
    name="count_rules",
    func=lambda *args, **kwargs: count_rules(),
    description="Count total rules. Use for 'how many rules', 'count rules', 'number of rules'"
)

class FindKeywordInput(BaseModel):
    """Input schema for finding by keyword"""
    keyword: str = Field(description="Keyword to search for in rule names and descriptions")

find_keyword_tool = StructuredTool(
    name="find_rule_by_keyword",
    func=find_rule_by_keyword_wrapper,  # ← Using wrapper
    description="Find rules by keyword in name/description. Use for 'find rules with', 'search for', 'rules containing'",
    args_schema=FindKeywordInput
)


class FindIPInput(BaseModel):
    """Input schema for finding by IP"""
    ip_address: str = Field(description="IP address to search for in source or destination")

find_ip_tool = StructuredTool(
    name="find_rules_by_ip",
    func=find_rules_by_ip_wrapper,  # ← Using wrapper
    description="Find rules by IP address. Use when user mentions an IP like '10.0.0.1'",
    args_schema=FindIPInput
)

class FindPortInput(BaseModel):
    """Input schema for finding by port"""
    port: str = Field(description="Port number to search for")

find_port_tool = StructuredTool(
    name="find_rules_by_port",
    func=find_rules_by_port,
    description="Find rules by port number. Use for 'port 80', 'port 443', 'what uses port X'",
    args_schema=FindPortInput
)

get_allow_rules_tool = Tool(
    name="get_allow_rules",
    func=lambda *args, **kwargs: get_allow_rules(),
    description="List all allow rules. Use for 'show allow rules', 'permitted traffic', 'allowed rules'"
)

get_deny_rules_tool = Tool(
    name="get_deny_rules",
    func=lambda *args, **kwargs: get_deny_rules(),
    description="List all deny rules. Use for 'show deny rules', 'blocked traffic', 'denied rules'"
)

class GetRuleDetailsInput(BaseModel):
    """Input schema for getting rule details"""
    rule_name: str = Field(description="Name of the rule to get details for")

get_rule_details_tool = StructuredTool(
    name="get_rule_details",
    func=get_rule_details_wrapper,  # ← Using wrapper
    description="Get full details of a specific rule. Use for 'details of X', 'show me rule X', 'info about X'",
    args_schema=GetRuleDetailsInput
)

summarize_rules_tool = Tool(
    name="summarize_rules",
    func=lambda *args, **kwargs: summarize_rules(),
    description="Get overview/summary of all rules. Use for 'summary', 'overview', 'statistics', 'stats'"
)

class CheckExistsInput(BaseModel):
    """Input schema for checking if rule exists"""
    rule_name: str = Field(description="Name of the rule to check")

check_exists_tool = StructuredTool(
    name="check_rule_exists",
    func=check_rule_exists_wrapper,  # ← Using wrapper
    description="Check if a rule exists. Use for 'does X exist', 'is there a rule called X'",
    args_schema=CheckExistsInput
)

class DeleteContainingInput(BaseModel):
    """Input schema for deleting rules by keyword"""
    keyword: str = Field(description="Keyword to search for in rules to delete")

delete_containing_tool = StructuredTool(
    name="delete_rules_containing",
    func=delete_rules_containing_wrapper,  # ← Using wrapper
    description="Delete all rules with keyword. Use for 'delete all rules with', 'remove rules containing'",
    args_schema=DeleteContainingInput
)


class DisableRuleInput(BaseModel):
    """Input schema for disabling a rule"""
    rule_name: str = Field(description="Name of the rule to disable")

disable_rule_tool = StructuredTool(
    name="disable_rule",
    func=disable_rule_wrapper,  # ← Using wrapper
    description="Disable a rule (adds DISABLED- prefix). Use for 'disable', 'turn off', 'deactivate'",
    args_schema=DisableRuleInput
)

class EnableRuleInput(BaseModel):
    """Input schema for enabling a rule"""
    rule_name: str = Field(description="Name of the disabled rule to enable")

enable_rule_tool = StructuredTool(
    name="enable_rule",
    func=enable_rule_wrapper,  # ← Using wrapper
    description="Re-enable a disabled rule. Use for 'enable', 'turn on', 'activate'",
    args_schema=EnableRuleInput
)


duplicate_rule_tool = StructuredTool(
    name="duplicate_rule",
    func=duplicate_rule,
    description="Copy/clone an existing rule. Use for 'copy rule', 'duplicate rule', 'clone rule'",
    args_schema=DuplicateRuleInput
)

get_recent_tool = StructuredTool(
    name="get_recent_rules",
    func=get_recent_rules,
    description="Get N most recent rules. Use for 'recent rules', 'last X rules', 'newest rules'",
    args_schema=GetRecentInput
)

get_last_rule_tool = Tool(
    name="get_last_rule",
    func=lambda *args, **kwargs: get_last_rule(),
    description="Get name of last rule. Use when user says 'last rule', 'bottom rule'"
)

get_first_rule_tool = Tool(
    name="get_first_rule",
    func=lambda *args, **kwargs: get_first_rule(),
    description="Get name of first rule. Use when user says 'first rule', 'top rule'"
)

get_rule_position_tool = Tool.from_function(
    func=get_rule_at_position,
    name="get_rule_at_position",
    description="Get rule name at position. Use for '3rd rule', 'rule number 5'"
)

ALL_TOOLS = [
    # Original tools
    list_csv_tool, 
    add_rule_tool,
    validate_tool, 
    edit_rule_tool,
    delete_rule_tool, 
    reorder_rule_tool,
    list_firewall_tool,
    show_changes_tool,
    commit_tool,
    # Smart query tools
    count_rules_tool,
    find_keyword_tool,
    find_ip_tool,
    find_port_tool,
    get_allow_rules_tool,
    get_deny_rules_tool,
    get_rule_details_tool,
    summarize_rules_tool,
    check_exists_tool,
    # Smart action tools
    disable_rule_tool,
    enable_rule_tool,
    duplicate_rule_tool,
    get_recent_tool,
    delete_containing_tool,
    # Position tools
    get_last_rule_tool,
    get_first_rule_tool,
    get_rule_position_tool
]




# ============= AGENT CREATION =============

@st.cache_resource
def create_agent():
    """Create the LangChain agent with natural language understanding (cached)"""
    llm = ChatAnthropic(
        model="claude-sonnet-4-5-20250929",
        temperature=0.3  # Higher temp for better conversation
    )
    
    # Bind tools to the model (LangChain 1.0+ way)
    llm_with_tools = llm.bind_tools(ALL_TOOLS)
    
    return llm_with_tools

def get_system_prompt():
    """Get the intelligent system prompt for natural language understanding"""
    return """You are an intelligent Palo Alto firewall management assistant with advanced natural language understanding.

🧠 CORE CAPABILITIES:
1. **Understand Intent** - Interpret what users want even with casual language
2. **Extract Information** - Pull IPs, ports, protocols from natural text
3. **Smart Defaults** - Fill in reasonable values when not specified
4. **Ask Clarifying Questions** - When critical info is missing, ask specifically

🔍 INTENT RECOGNITION:
**Actions:**
- "block", "deny", "stop", "prevent" → deny action
- "allow", "permit", "let", "enable" → allow action
- "remove", "delete" → delete operation
- "show", "list", "display" → list operation

**Services (auto-detect port & protocol):**
- "ssh" → port 22, tcp
- "web" or "http" → port 80, tcp
- "https" or "ssl" → port 443, tcp
- "database" or "mysql" → port 3306, tcp

**IP Extraction:**
- Look for X.X.X.X patterns
- "from anywhere" → source: "any"
- "to anywhere" → destination: "any"

📋 EXAMPLES:
"block traffic from 10.0.0.5" → deny rule, source=10.0.0.5, dest=any
"let me ssh to 192.168.1.10" → allow rule, service=ssh, dest=192.168.1.10
"show me web rules" → search for http/https/port 80/443
"remove that ssh rule" → search ssh, then ask which to delete

⚡ WORKFLOW:
1. Parse natural language
2. Extract available info
3. If complete → execute
4. If missing info → ask ONE specific question
5. Summarize actions clearly

Remember: Have a conversation, not just execute commands!"""


# ============= STREAMLIT UI =============

def main():
    apply_dark_security_theme()
    # Initialize session state
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    if 'username' not in st.session_state:
        st.session_state.username = "demo_user"
    
    # Sidebar
    with st.sidebar:
        st.title("🔥 Firewall Manager")
        st.markdown("---")
        
        # User info
        st.subheader("👤 User")
        username = st.text_input("Username", value=st.session_state.username)
        st.session_state.username = username
        
        st.markdown("---")
        
        # Quick actions
        st.subheader("⚡ Quick Actions")
        
        if st.button("📋 View CSV Rules"):
            with st.spinner("Loading..."):
                result = list_csv_rules()
                st.text_area("CSV Rules", result, height=400)
        
        if st.button("🔥 View Firewall Rules"):
            with st.spinner("Connecting to firewall..."):
                result = list_firewall_rules()
                st.text_area("Firewall Rules", result, height=400)
        
        st.markdown("---")
        
        
        # Stats
        st.subheader("📊 System Status")
        try:
            df = pd.read_csv(CSV_PATH)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("CSV Rules", len(df))
                st.markdown("🟢 **Active**")
            
            with col2:
                allow_count = len(df[df['action'] == 'allow'])
                deny_count = len(df[df['action'] == 'deny'])
                st.metric("Allow", allow_count)
                st.metric("Deny", deny_count)
                
        except:
            st.warning("⚠️ No CSV file found")
    
    # Main area
    st.markdown("""
        <div style='text-align: center; padding: 1rem 0;'>
            <h1 style='color: #58a6ff; margin: 0;'>🔥 Firewall Manager</h1>
            <p style='color: #8b949e; margin: 0.5rem 0;'>Intelligent Security Operations Assistant</p>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 💬 Command Center")
    st.markdown("Ask me anything about your firewall rules!")
    
    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Chat input
    if prompt := st.chat_input("What would you like to do?"):
        # Add user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Get agent response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    llm_with_tools = create_agent()
                    
                    # Use intelligent system prompt
                    system_msg = get_system_prompt()
                    
                    # Build conversation with history
                    messages = [{"role": "system", "content": system_msg}]
                    
                    # Add recent conversation history (last 5 exchanges)
                    recent_messages = st.session_state.messages[-10:] if len(st.session_state.messages) > 10 else st.session_state.messages
                    for msg in recent_messages:
                        messages.append({
                            "role": "user" if msg["role"] == "user" else "assistant",
                            "content": msg["content"]
                        })
                    
                    # Add current prompt
                    messages.append({"role": "user", "content": prompt})
                    
                    # Invoke with tool calling
                    response = llm_with_tools.invoke(messages)
                    
                    # Check if tools were called
                    if hasattr(response, 'tool_calls') and response.tool_calls:
                        # Execute tool calls
                        tool_outputs = []
                        for tool_call in response.tool_calls:
                            tool_name = tool_call['name']
                            tool_args = tool_call['args']
                            
                            # Find and execute the tool
                            for tool in ALL_TOOLS:
                                if tool.name == tool_name:
                                    try:
                                        result = tool.func(**tool_args) if hasattr(tool_args, '__iter__') and not isinstance(tool_args, str) else tool.func(tool_args)
                                        tool_outputs.append(result)
                                    except Exception as e:
                                        tool_outputs.append(f"Error: {str(e)}")
                                    break
                        
                        # Show tool results
                        answer = "\n\n".join(tool_outputs) if tool_outputs else response.content
                    else:
                        answer = response.content
                    
                    st.markdown(answer)
                    st.session_state.messages.append({"role": "assistant", "content": answer})
                except Exception as e:
                    error_msg = f"❌ Error: {str(e)}"
                    st.error(error_msg)
                    st.session_state.messages.append({"role": "assistant", "content": error_msg})


if __name__ == "__main__":
    # Check for API key
    if not os.environ.get('ANTHROPIC_API_KEY'):
        st.error(" ANTHROPIC_API_KEY not set!")
        st.info("Set it with: export ANTHROPIC_API_KEY='your-key-here'")
        st.stop()
    
    main()