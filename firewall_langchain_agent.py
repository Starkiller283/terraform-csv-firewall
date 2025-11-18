"""
Palo Alto Firewall Manager - LangChain Version
Conversational agent for managing firewall rules via LangChain
"""

from langchain.tools import Tool, StructuredTool
from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from pydantic import BaseModel, Field
import pandas as pd
import os
from pathlib import Path
from git import Repo
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============= CONFIGURATION =============
# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.absolute()
CSV_PATH = str(SCRIPT_DIR / "rules.csv")
REPO_PATH = str(SCRIPT_DIR)

# Firewall connection - uses API key
FIREWALL_IP = "192.168.0.200"
API_KEY = "LUFRPT1wOU12bXpFZG9YZ2FBV1VRWFpWRU11OEltYzQ9ZytqWjRUUSt4bnhsbVY2VEtGbTIvSTV0QnVEKzErdGJsV3JscEcxOXk4NUhzRzFTcUZlcHVYTjNHSm5zWnBnMw=="

FIREWALL_CONNECTED = True
API_BASE = f"https://{FIREWALL_IP}/restapi/v10.2"


# ============= CSV OPERATIONS FUNCTIONS =============

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


def search_csv_rule(search_term: str) -> str:
    """
    Search for rules in CSV by name or description.
    
    Args:
        search_term: Term to search for in rule names and descriptions
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


def add_rule_to_csv(rule_name: str, source_ip: str, destination_ip: str, 
                    port: str, protocol: str, action: str, description: str) -> str:
    """
    Add a new firewall rule to the CSV file.
    This does NOT deploy yet - you need to commit and push to trigger GitHub Actions.
    
    Args:
        rule_name: Name for the firewall rule
        source_ip: Source IP address or CIDR range
        destination_ip: Destination IP address or CIDR range
        port: Port number
        protocol: Protocol (tcp, udp, icmp, etc)
        action: Action to take (allow or deny)
        description: Human-readable description of the rule
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


def delete_rule_from_csv(rule_name: str) -> str:
    """
    Delete a rule from the CSV file by name.
    
    Args:
        rule_name: Name of the rule to delete
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


def edit_csv_rule(rule_name: str, source_ip: str = None, destination_ip: str = None,
                  port: str = None, protocol: str = None, action: str = None, 
                  description: str = None) -> str:
    """
    Edit an existing rule in CSV. Only provide the fields you want to change.
    
    Args:
        rule_name: Name of the rule to edit (required)
        source_ip: New source IP (optional)
        destination_ip: New destination IP (optional)
        port: New port (optional)
        protocol: New protocol (optional)
        action: New action (optional)
        description: New description (optional)
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


# ============= FIREWALL OPERATIONS FUNCTIONS =============

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


# ============= GIT OPERATIONS FUNCTIONS =============

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
        
        csv_filename = Path(CSV_PATH).name
        if csv_filename not in changed_files:
            return f"No changes to {csv_filename}"
        
        diff = repo.git.diff(CSV_PATH)
        
        return f"📝 Pending changes to {csv_filename}:\n\n{diff}\n\n⚠️ Remember to commit and push to deploy!"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"


def commit_and_push_changes(commit_message: str) -> str:
    """
    Commit CSV changes and push to GitHub. This triggers your GitHub Actions pipeline.
    
    Args:
        commit_message: Description of the changes being committed
    """
    try:
        repo = Repo(REPO_PATH)
        
        # Check if there are changes
        if not repo.is_dirty(untracked_files=True):
            return "Nothing to commit - no changes detected"
        
        # Add CSV file
        repo.index.add([CSV_PATH])
        
        # Commit
        repo.index.commit(commit_message)
        
        # Push
        origin = repo.remote(name='origin')
        origin.push()
        
        return f"""
✅ Changes committed and pushed!
📝 Commit message: "{commit_message}"

🚀 GitHub Actions pipeline should now be running...
   Check: https://github.com/YOUR-REPO/actions
"""
        
    except Exception as e:
        return f"❌ Git error: {str(e)}"


# ============= PYDANTIC SCHEMAS FOR COMPLEX TOOLS =============

class AddRuleInput(BaseModel):
    """Input schema for adding a firewall rule"""
    rule_name: str = Field(description="Name for the firewall rule (must be unique)")
    source_ip: str = Field(description="Source IP address or CIDR range (e.g., 10.0.0.1 or 192.168.1.0/24)")
    destination_ip: str = Field(description="Destination IP address or CIDR range")
    port: str = Field(description="Port number (e.g., 22, 80, 443)")
    protocol: str = Field(description="Protocol: tcp, udp, or icmp")
    action: str = Field(description="Action to take: allow or deny")
    description: str = Field(description="Human-readable description of what this rule does")


class EditRuleInput(BaseModel):
    """Input schema for editing a firewall rule"""
    rule_name: str = Field(description="Name of the rule to edit")
    source_ip: str = Field(default=None, description="New source IP (optional)")
    destination_ip: str = Field(default=None, description="New destination IP (optional)")
    port: str = Field(default=None, description="New port (optional)")
    protocol: str = Field(default=None, description="New protocol (optional)")
    action: str = Field(default=None, description="New action (optional)")
    description: str = Field(default=None, description="New description (optional)")


# ============= CREATE LANGCHAIN TOOLS =============

# Simple tools (no parameters or single parameter)
list_csv_tool = Tool(
    name="list_csv_rules",
    func=list_csv_rules,
    description="Show all firewall rules defined in the CSV file (your infrastructure as code). Use this to see what rules are configured."
)

search_csv_tool = Tool.from_function(
    func=search_csv_rule,
    name="search_csv_rule",
    description="Search for firewall rules in CSV by name or description. Useful for finding specific rules."
)

delete_rule_tool = Tool.from_function(
    func=delete_rule_from_csv,
    name="delete_rule_from_csv",
    description="Delete a firewall rule from the CSV file by name. Remember to commit and push after."
)

list_firewall_tool = Tool(
    name="list_firewall_rules",
    func=list_firewall_rules,
    description="Show all security rules currently active on the actual Palo Alto firewall. Use this to see deployed rules."
)

show_changes_tool = Tool(
    name="show_pending_changes",
    func=show_pending_changes,
    description="Show what changes have been made to the CSV that haven't been committed yet."
)

commit_push_tool = Tool.from_function(
    func=commit_and_push_changes,
    name="commit_and_push_changes",
    description="Commit CSV changes and push to GitHub, which triggers the deployment pipeline."
)

# Complex tools (multiple parameters) - use StructuredTool
add_rule_tool = StructuredTool(
    name="add_rule_to_csv",
    func=add_rule_to_csv,
    description="Add a new firewall rule to the CSV file. This does NOT deploy immediately - user needs to commit and push.",
    args_schema=AddRuleInput
)

edit_rule_tool = StructuredTool(
    name="edit_csv_rule",
    func=edit_csv_rule,
    description="Edit an existing firewall rule in the CSV. Only provide the fields that need to change.",
    args_schema=EditRuleInput
)

# Collect all tools
ALL_TOOLS = [
    list_csv_tool,
    search_csv_tool,
    add_rule_tool,
    edit_rule_tool,
    delete_rule_tool,
    list_firewall_tool,
    show_changes_tool,
    commit_push_tool,
]


# ============= AGENT SETUP =============

def create_firewall_agent():
    """Create and return the LangChain agent executor"""
    
    # Initialize Claude (you can also use ChatOpenAI if you prefer)
    llm = ChatAnthropic(
        model="claude-3-5-sonnet-20241022",
        temperature=0,
        # api_key="your-api-key-here"  # or set ANTHROPIC_API_KEY env var
    )
    
    # Create the prompt
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a helpful Palo Alto firewall management assistant. You help users manage their firewall rules through a GitOps workflow.

Key things to remember:
1. Rules added/edited/deleted in CSV are NOT immediately deployed - users must commit and push
2. Always remind users about the commit & push step after making changes
3. The CSV file is the source of truth for infrastructure as code
4. When adding rules, make sure to get all required information: rule_name, source_ip, destination_ip, port, protocol, action, and description
5. Common protocols are: tcp, udp, icmp
6. Actions are either: allow or deny
7. IP addresses can be single IPs (10.0.0.1) or CIDR ranges (192.168.1.0/24)

Be conversational and helpful!"""),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])
    
    # Create the agent
    agent = create_tool_calling_agent(llm, ALL_TOOLS, prompt)
    
    # Create the executor
    agent_executor = AgentExecutor(
        agent=agent,
        tools=ALL_TOOLS,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=10
    )
    
    return agent_executor


# ============= MAIN CONVERSATION LOOP =============

def main():
    """Run the interactive firewall management agent"""
    print("=" * 60)
    print("🔥 Palo Alto Firewall Manager - LangChain Agent")
    print("=" * 60)
    print(f"📂 CSV Path: {CSV_PATH}")
    print(f"📂 Repo Path: {REPO_PATH}")
    print(f"🔥 Firewall: {FIREWALL_IP}")
    print("=" * 60)
    print("\nInitializing agent...")
    
    try:
        agent = create_firewall_agent()
        print("✅ Agent ready!\n")
        print("Type your questions or commands. Examples:")
        print("  - 'Show me all my CSV rules'")
        print("  - 'Add a rule to allow SSH from 10.0.0.5 to 10.0.1.10'")
        print("  - 'Delete the rule named allow-ssh'")
        print("  - 'What rules are on the firewall?'")
        print("  - 'Show pending changes'")
        print("\nType 'exit', 'quit', or 'q' to exit.\n")
        
        # Conversation loop
        while True:
            try:
                user_input = input("\n🧑 You: ").strip()
                
                if not user_input:
                    continue
                    
                if user_input.lower() in ['exit', 'quit', 'q']:
                    print("\n👋 Goodbye!")
                    break
                
                print("\n🤖 Assistant: ", end="", flush=True)
                
                # Run the agent
                response = agent.invoke({"input": user_input})
                print(response['output'])
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Error: {str(e)}")
                print("Please try again or type 'exit' to quit.")
    
    except Exception as e:
        print(f"\n❌ Failed to initialize agent: {str(e)}")
        print("\nMake sure you have:")
        print("  1. Set ANTHROPIC_API_KEY environment variable")
        print("  2. Installed required packages: pip install langchain langchain-anthropic pandas gitpython requests")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())