"""
Manual Firewall Management Page
Direct interface for managing rules without chat
"""

import streamlit as st
import pandas as pd
import os
from pathlib import Path
from git import Repo
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime

# Import from parent directory
import sys
sys.path.append(str(Path(__file__).parent.parent))
from palo_alto_validation import PaloAltoValidator

# Configuration
SCRIPT_DIR = Path(__file__).parent.parent.absolute()
CSV_PATH = str(SCRIPT_DIR / "rules.csv")
FIREWALL_IP = "192.168.0.18"
API_KEY = "LUFRPT1wOU12bXpFZG9YZ2FBV1VRWFpWRU11OEltYzQ9ZytqWjRUUSt4bnhsbVY2VEtGbTIvSTV0QnVEKzErdGJsV3JscEcxOXk4NUhzRzFTcUZlcHVYTjNHSm5zWnBnMw=="

# Apply same dark theme
def apply_dark_security_theme():
    """Apply dark cybersecurity theme"""
    st.markdown("""
    <style>
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #161b22 0%, #0d1117 100%);
        border-right: 1px solid #30363d;
    }
    
    .stTextInput > div > div > input,
    .stTextArea textarea,
    .stSelectbox > div > div {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px;
    }
    
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
    
    h1, h2, h3 {
        color: #58a6ff !important;
        font-weight: 700;
    }
    
    [data-testid="stMetricValue"] {
        color: #58a6ff;
    }
    
    .rule-card {
        background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        transition: all 0.3s ease;
    }
    
    .rule-card:hover {
        border-color: #58a6ff;
        box-shadow: 0 0 20px rgba(88, 166, 255, 0.2);
        transform: translateX(5px);
    }
    
    .rule-header {
        color: #58a6ff;
        font-weight: 600;
        font-size: 1.1rem;
        margin-bottom: 0.5rem;
    }
    
    .rule-detail {
        color: #8b949e;
        font-family: 'Fira Code', monospace;
        font-size: 0.9rem;
        line-height: 1.6;
    }
    
    .action-allow {
        color: #3fb950;
        font-weight: 600;
    }
    
    .action-deny {
        color: #f85149;
        font-weight: 600;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        background-color: #161b22;
        border-radius: 8px;
        padding: 0.5rem;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: #8b949e;
        background-color: transparent;
    }
    
    .stTabs [aria-selected="true"] {
        color: #58a6ff;
        background-color: #0d1117;
    }
    
    .stExpander {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
    }
    
    ::-webkit-scrollbar {
        width: 10px;
        background-color: #0d1117;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #30363d 0%, #21262d 100%);
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

# Helper functions
def load_rules():
    """Load rules from CSV"""
    try:
        df = pd.read_csv(CSV_PATH)
        return df
    except:
        return pd.DataFrame(columns=['rule_name', 'source_ip', 'destination_ip', 'port', 'protocol', 'action', 'description'])

def save_rules(df):
    """Save rules to CSV"""
    df.to_csv(CSV_PATH, index=False)

def display_rule_card(rule):
    """Display a rule as a nice card"""
    action_class = "action-allow" if rule['action'] == 'allow' else "action-deny"
    status_icon = "🟢" if rule['action'] == 'allow' else "🔴"
    
    st.markdown(f"""
    <div class="rule-card">
        <div class="rule-header">{status_icon} {rule['rule_name']}</div>
        <div class="rule-detail">
            <strong>Source:</strong> {rule['source_ip']} → <strong>Destination:</strong> {rule['destination_ip']}<br>
            <strong>Port:</strong> {rule['port']} | <strong>Protocol:</strong> {rule['protocol']}<br>
            <strong>Action:</strong> <span class="{action_class}">{rule['action'].upper()}</span><br>
            <strong>Description:</strong> {rule['description']}
        </div>
    </div>
    """, unsafe_allow_html=True)

def add_rule_to_csv(rule_name, source_ip, destination_ip, port, protocol, action, description):
    """Add a new rule with validation"""
    rule_data = {
        'rule_name': rule_name,
        'source_ip': source_ip,
        'destination_ip': destination_ip,
        'port': port,
        'protocol': protocol,
        'action': action,
        'description': description
    }
    
    # Validate
    is_valid, messages = PaloAltoValidator.validate_all(rule_data)
    
    if not is_valid:
        return False, "\n".join(messages)
    
    # Check for duplicates
    df = load_rules()
    if rule_name in df['rule_name'].values:
        return False, f"Rule '{rule_name}' already exists"
    
    # Add rule
    new_rule = pd.DataFrame([rule_data])
    df = pd.concat([df, new_rule], ignore_index=True)
    save_rules(df)
    
    return True, "Rule added successfully!"

def delete_rule(rule_name):
    """Delete a rule"""
    df = load_rules()
    if rule_name not in df['rule_name'].values:
        return False, f"Rule '{rule_name}' not found"
    
    df = df[df['rule_name'] != rule_name]
    save_rules(df)
    return True, f"Rule '{rule_name}' deleted"

def commit_and_push(commit_message):
    """Commit and push changes"""
    try:
        repo = Repo(SCRIPT_DIR)
        
        if not repo.is_dirty() and not repo.untracked_files:
            return False, "No changes to commit"
        
        repo.index.add(['rules.csv'])
        commit = repo.index.commit(commit_message)
        origin = repo.remote(name='origin')
        origin.push()
        
        return True, f"✅ Changes deployed! Commit: {commit.hexsha[:7]}"
    except Exception as e:
        return False, f"Error: {str(e)}"

# Main page
def main():
    apply_dark_security_theme()
    
    st.markdown("""
        <div style='text-align: center; padding: 1rem 0;'>
            <h1 style='color: #58a6ff; margin: 0;'>⚙️ Manual Rule Management</h1>
            <p style='color: #8b949e; margin: 0.5rem 0;'>Direct control over firewall rules</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Create tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📋 View Rules", "➕ Add Rule", "✏️ Edit Rule", "🚀 Deploy"])
    
    # TAB 1: View Rules
    with tab1:
        st.subheader("Current Firewall Rules")
        
        df = load_rules()
        
        if df.empty:
            st.info("No rules found. Add your first rule in the 'Add Rule' tab!")
        else:
            # Filters
            col1, col2, col3 = st.columns(3)
            with col1:
                filter_action = st.selectbox("Filter by Action", ["All", "allow", "deny"])
            with col2:
                filter_protocol = st.selectbox("Filter by Protocol", ["All"] + list(df['protocol'].unique()))
            with col3:
                search_term = st.text_input("🔍 Search rules", placeholder="Search by name...")
            
            # Apply filters
            filtered_df = df.copy()
            if filter_action != "All":
                filtered_df = filtered_df[filtered_df['action'] == filter_action]
            if filter_protocol != "All":
                filtered_df = filtered_df[filtered_df['protocol'] == filter_protocol]
            if search_term:
                filtered_df = filtered_df[filtered_df['rule_name'].str.contains(search_term, case=False, na=False)]
            
            st.markdown(f"**Showing {len(filtered_df)} of {len(df)} rules**")
            
            # Display rules
            for idx, rule in filtered_df.iterrows():
                col1, col2 = st.columns([5, 1])
                with col1:
                    display_rule_card(rule)
                with col2:
                    st.write("")  # Spacing
                    if st.button("🗑️ Delete", key=f"del_{idx}"):
                        success, message = delete_rule(rule['rule_name'])
                        if success:
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
    
    # TAB 2: Add Rule
    with tab2:
        st.subheader("Add New Firewall Rule")
        
        with st.form("add_rule_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                rule_name = st.text_input("Rule Name*", placeholder="e.g., allow-ssh-admin")
                source_ip = st.text_input("Source IP*", placeholder="e.g., 10.0.0.0/24 or any")
                destination_ip = st.text_input("Destination IP*", placeholder="e.g., 192.168.1.10 or any")
            
            with col2:
                port = st.text_input("Port*", placeholder="e.g., 22, 80, or any")
                protocol = st.selectbox("Protocol*", ["tcp", "udp", "icmp", "any"])
                action = st.selectbox("Action*", ["allow", "deny"])
            
            description = st.text_area("Description*", placeholder="Describe what this rule does...")
            
            submitted = st.form_submit_button("➕ Add Rule", use_container_width=True)
            
            if submitted:
                if not all([rule_name, source_ip, destination_ip, port, protocol, action, description]):
                    st.error("❌ Please fill in all fields")
                else:
                    with st.spinner("Adding rule..."):
                        success, message = add_rule_to_csv(
                            rule_name, source_ip, destination_ip, 
                            port, protocol, action, description
                        )
                    
                    if success:
                        st.success(f"✅ {message}")
                        st.info("💡 Don't forget to deploy your changes in the 'Deploy' tab!")
                        st.balloons()
                    else:
                        st.error(f"❌ {message}")
    
    # TAB 3: Edit Rule
    with tab3:
        st.subheader("Edit Existing Rule")
        
        df = load_rules()
        
        if df.empty:
            st.info("No rules to edit. Add some rules first!")
        else:
            rule_to_edit = st.selectbox("Select Rule to Edit", df['rule_name'].tolist())
            
            if rule_to_edit:
                current_rule = df[df['rule_name'] == rule_to_edit].iloc[0]
                
                with st.form("edit_rule_form"):
                    st.markdown(f"**Editing:** `{rule_to_edit}`")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        new_source = st.text_input("Source IP", value=current_rule['source_ip'])
                        new_dest = st.text_input("Destination IP", value=current_rule['destination_ip'])
                    
                    with col2:
                        new_port = st.text_input("Port", value=current_rule['port'])
                        
                        # Handle protocols safely
                        protocol_options = ["tcp", "udp", "icmp", "any", "ssl", "http", "https"]
                        current_protocol = str(current_rule['protocol']).lower()
                        if current_protocol in protocol_options:
                            protocol_index = protocol_options.index(current_protocol)
                        else:
                            protocol_index = 0
                            st.warning(f"⚠️ Protocol '{current_protocol}' not in list, defaulting to 'tcp'")
                        
                        new_protocol = st.selectbox("Protocol", protocol_options, index=protocol_index)
                        
                        # Handle actions safely
                        action_options = ["allow", "deny"]
                        current_action = str(current_rule['action']).lower()
                        if current_action in action_options:
                            action_index = action_options.index(current_action)
                        else:
                            action_index = 0
                            st.warning(f"⚠️ Action '{current_action}' not in list, defaulting to 'allow'")
                        
                        new_action = st.selectbox("Action", action_options, index=action_index)
                    
                    new_desc = st.text_area("Description", value=current_rule['description'])
                    
                    col_a, col_b = st.columns(2)
                    with col_a:
                        update_submitted = st.form_submit_button("💾 Update Rule", use_container_width=True)
                    with col_b:
                        delete_submitted = st.form_submit_button("🗑️ Delete Rule", use_container_width=True)
                    
                    if update_submitted:
                        # Update the rule
                        idx = df[df['rule_name'] == rule_to_edit].index[0]
                        df.at[idx, 'source_ip'] = new_source
                        df.at[idx, 'destination_ip'] = new_dest
                        df.at[idx, 'port'] = new_port
                        df.at[idx, 'protocol'] = new_protocol
                        df.at[idx, 'action'] = new_action
                        df.at[idx, 'description'] = new_desc
                        
                        save_rules(df)
                        st.success(f"✅ Rule '{rule_to_edit}' updated!")
                        st.info("💡 Deploy your changes in the 'Deploy' tab!")
                        st.rerun()
                    
                    if delete_submitted:
                        success, message = delete_rule(rule_to_edit)
                        if success:
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
    
    # TAB 4: Deploy
    with tab4:
        st.subheader("Deploy Changes to Firewall")
        
        try:
            repo = Repo(SCRIPT_DIR)
            
            if not repo.is_dirty(untracked_files=True):
                st.success("✅ No pending changes - everything is deployed!")
            else:
                st.warning("⚠️ You have uncommitted changes")
                
                # Show diff
                with st.expander("📝 View Changes"):
                    try:
                        diff = repo.git.diff(CSV_PATH)
                        st.code(diff, language="diff")
                    except:
                        st.text("Changes detected in rules.csv")
                
                # Commit form
                with st.form("deploy_form"):
                    commit_msg = st.text_input(
                        "Commit Message",
                        value=f"Update firewall rules - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                        placeholder="Describe your changes..."
                    )
                    
                    deploy_btn = st.form_submit_button("🚀 Deploy to Firewall", use_container_width=True)
                    
                    if deploy_btn:
                        with st.spinner("Deploying changes..."):
                            success, message = commit_and_push(commit_msg)
                        
                        if success:
                            st.success(message)
                            st.info("Your GitHub Actions pipeline is now running. Changes will be deployed to the firewall in ~2 minutes.")
                            st.balloons()
                        else:
                            st.error(message)
        
        except Exception as e:
            st.error(f"Git error: {str(e)}")
            st.info("Make sure you're in a git repository with proper configuration.")
    
    # Sidebar with stats
    with st.sidebar:
        st.subheader("📊 System Status")
        
        df = load_rules()
        
        if not df.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Total Rules", len(df))
                st.markdown("🟢 **Active**")
            
            with col2:
                allow_count = len(df[df['action'] == 'allow'])
                deny_count = len(df[df['action'] == 'deny'])
                st.metric("Allow", allow_count)
                st.metric("Deny", deny_count)
        
        st.markdown("---")
        
        st.subheader("💡 Quick Tips")
        st.markdown("""
        - **View Rules:** See all current rules with filters
        - **Add Rule:** Create new rules with validation
        - **Edit Rule:** Modify existing rules
        - **Deploy:** Push changes to firewall via GitOps
        
        All changes are validated before saving!
        """)

if __name__ == "__main__":
    main()