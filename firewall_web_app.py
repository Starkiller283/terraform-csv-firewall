"""
Firewall Manager - Web Application (Streamlit)
Multi-user web interface for managing Palo Alto firewall rules

To run: streamlit run firewall_web_app.py
Access at: http://localhost:8501
"""

import streamlit as st
import pandas as pd
import os
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
                    port: str, protocol: str, action: str, description: str) -> str:
    """Add a new firewall rule to CSV"""
    try:
        df = pd.read_csv(CSV_PATH)
        
        if rule_name in df['rule_name'].values:
            return f"❌ Rule '{rule_name}' already exists in CSV"
        
        new_rule = pd.DataFrame([{
            'rule_name': rule_name,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'port': port,
            'protocol': protocol,
            'action': action,
            'description': description
        }])
        
        df = pd.concat([df, new_rule], ignore_index=True)
        df.to_csv(CSV_PATH, index=False)
        
        # Log the change
        log_change(st.session_state.get('username', 'unknown'), 'ADD', rule_name)
        
        return f"✅ Rule '{rule_name}' added to CSV!"
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

delete_rule_tool = Tool.from_function(
    func=delete_rule_from_csv,
    name="delete_rule_from_csv",
    description="Delete a firewall rule from CSV"
)

def list_firewall_rules_wrapper(*args, **kwargs):
    """Wrapper to handle any extra arguments from LangChain"""
    return list_firewall_rules()

# Update tool definition
list_firewall_tool = Tool(
    name="list_firewall_rules",
    func=list_firewall_rules_wrapper,
    description="Show rules on the actual firewall"
)

ALL_TOOLS = [list_csv_tool, add_rule_tool, delete_rule_tool, list_firewall_tool]


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