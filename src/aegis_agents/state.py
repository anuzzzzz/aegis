import json
from typing import TypedDict, Literal

# The 'next_node' literal type defines the possible routing decisions
# The Detector Agent will choose one of these paths.
RoutingDecision = Literal["investigate", "false_positive"]

class AgentState(TypedDict):
    """
    Defines the shared state for the agent graph.
    """
    
    # The initial raw event (e.g., a GuardDuty finding)
    # This will be loaded from your synthetic JSON files.
    raw_event: dict
    
    # The analysis result from the Detector Agent
    analysis: str
    
    # The routing decision made by the Detector Agent
    next_node: RoutingDecision