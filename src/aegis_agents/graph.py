from langgraph.graph import StateGraph, END
from .state import AgentState
from .agents.detector_agent import run_detector_agent

# --- Define Placeholder Agents ---
# These are dummy functions for the agents you and your colleagues
# will build next. This allows you to build and test the graph now.

def run_investigator_agent(state: AgentState) -> dict:
    print("--- 🕵️ RUNNING INVESTIGATOR AGENT (Placeholder) ---")
    print(f"  Received for investigation: {state['analysis']}")
    # This agent would perform enrichment, check logs, etc.
    return {"analysis": state['analysis'] + "\nINVESTIGATION: [Investigator ran]"}

def run_remediation_agent(state: AgentState) -> dict:
    print("--- 👨‍🚒 RUNNING REMEDIATION AGENT (Placeholder) ---")
    print("  Remediation steps would be suggested here.")
    return {}

def run_report_agent(state: AgentState) -> dict:
    print("--- 📝 RUNNING REPORT AGENT (Placeholder) ---")
    print("  Final report would be generated here.")
    return {}

# --- Build the Graph ---

def create_agent_graph() -> StateGraph:
    """
    Creates the main LangGraph for the AWS Security Copilot.
    """
    graph_builder = StateGraph(AgentState)
    
    # 1. Add Nodes
    # Each agent function is a node in the graph.
    graph_builder.add_node("detector", run_detector_agent)
    graph_builder.add_node("investigator", run_investigator_agent)
    graph_builder.add_node("remediator", run_remediation_agent)
    graph_builder.add_node("reporter", run_report_agent)
    
    # 2. Define Edges
    
    # The detector is the entry point
    graph_builder.set_entry_point("detector")
    
    # 3. Add Conditional Edges
    # This is the core logic. The 'detector' node's output
    # (in 'next_node' field of the state) determines where to go next.
    graph_builder.add_conditional_edges(
        "detector",
        
        # This function reads the 'next_node' field from the state
        lambda state: state["next_node"],
        
        # This maps the value of 'next_node' to a graph node
        {
            "investigate": "investigator",
            "false_positive": END  # If it's a false positive, end the graph.
        }
    )
    
    # 4. Add Normal Edges
    # For now, we'll create a simple linear flow after investigation.
    # You can make this more complex later.
    graph_builder.add_edge("investigator", "remediator")
    graph_builder.add_edge("remediator", "reporter")
    graph_builder.add_edge("reporter", END) # End graph after reporting
    
    return graph_builder.compile()