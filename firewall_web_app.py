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
            return "✅ No pending changes - CSV is clean"
        
        changed_files = [item.a_path for item in repo.index.diff(None)]
        if 'rules.csv' not in changed_files:
            return "No changes to rules.csv"
        
        diff = repo.git.diff(CSV_PATH)
        return f"📝 Pending changes:\n\n{diff}\n\n⚠️ Commit and push to deploy!"
    except Exception as e:
        return f"❌ Error: {str(e)}"

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
        
📝 Commit: {commit.hexsha[:7]} - {commit_message}
🚀 GitHub Actions running...
Check: https://github.com/starkiller283/actions
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
        return "✅ All parameters are valid!"
    elif is_valid and messages:
        return "✅ Valid with warnings:\n\n" + "\n\n".join(messages)
    else:
        return "❌ Validation errors:\n\n" + "\n\n".join(messages)
    


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

ALL_TOOLS = [
    list_csv_tool, 
    add_rule_tool,
    validate_tool, 
    edit_rule_tool,
    delete_rule_tool, 
    reorder_rule_tool,
    list_firewall_tool,
    show_changes_tool,
    commit_tool
]



# ============= AGENT CREATION =============

@st.cache_resource
def create_agent():
    """Create the LangChain agent (cached)"""
    llm = ChatAnthropic(
        model="claude-sonnet-4-5-20250929",
        temperature=0
    )
    
    # Bind tools to the model (LangChain 1.0+ way)
    llm_with_tools = llm.bind_tools(ALL_TOOLS)
    
    return llm_with_tools


# ============= STREAMLIT UI =============

def main():
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
        st.subheader("📊 Stats")
        try:
            df = pd.read_csv(CSV_PATH)
            st.metric("CSV Rules", len(df))
            st.metric("Allow Rules", len(df[df['action'] == 'allow']))
            st.metric("Deny Rules", len(df[df['action'] == 'deny']))
        except:
            st.warning("No CSV file found")
        
        st.markdown("---")
        
        if st.button("🗑️ Clear Chat"):
            st.session_state.messages = []
            st.rerun()
    
    # Main area
    st.title("💬 Chat with Firewall Manager")
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
                    
                    # Create system message
                    system_msg = """You are a helpful Palo Alto firewall management assistant. 
                    Help users manage their firewall rules. Be concise and clear.
                    You have access to tools to manage firewall rules."""
                    
                    messages = [
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": prompt}
                    ]
                    
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