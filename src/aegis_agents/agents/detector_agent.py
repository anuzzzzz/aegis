import os
import json
from textwrap import dedent
from ..state import AgentState

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.pydantic_v1 import BaseModel, Field
from langchain_aws import ChatBedrock

# Ensure you have your AWS credentials set up in your environment
# (e.g., in your .env file and loaded)
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION


# --- Pydantic Model for Structured Output ---
# This forces the LLM to return JSON in a specific format,
# which is much more reliable than parsing raw text.
class DetectionResult(BaseModel):
    """Structured output for the Detector Agent's analysis."""
    analysis: str = Field(
        description="A brief, one-paragraph analysis of the security event. Explain WHY it is or is not a threat."
    )
    is_threat: bool = Field(
        description="Boolean flag. True if the event is a potential threat, False if it is a false positive."
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] = Field(
        description="The assessed severity of the threat. Set to 'NONE' if it is a false positive."
    )

# --- LLM and Prompt Setup ---

def get_detector_llm():
    """
    Initializes the ChatBedrock model for the Detector Agent.
    """
    # Using Claude 3 Sonnet as it's a fast, powerful, and cost-effective model
    # available on Bedrock, aligning with the hackathon goals.
    return ChatBedrock(
        model_id="anthropic.claude-3-sonnet-20240229-v1:0",
        model_kwargs={"temperature": 0.0},
        region_name=os.environ.get("AWS_REGION", "us-east-1") 
    )

def get_detector_prompt():
    """
    Creates the prompt template for the Detector Agent.
    """
    system_prompt = dedent("""
    You are an expert AWS Security Analyst working in a Security Operations Center (SOC).
    Your job is to perform an initial triage of an incoming security event (in JSON format).
    
    Review the event and provide a concise analysis. Determine if it is a
    1.  **Potential Threat**: An event that requires further investigation.
    2.  **False Positive**: A benign event that can be safely ignored.
    
    Base your decision only on the provided event data.
    """)
    
    human_prompt = dedent("""
    **Security Event:**
    
    ```json
    {event_data}
    ```
    
    Please analyze this event and provide your triage decision in the requested JSON format.
    """)
    
    return ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", human_prompt),
    ])

# --- Agent Node Function ---

def run_detector_agent(state: AgentState) -> AgentState:
    """
    This is the function (node) that runs the Detector Agent.
    """
    print("--- 🔎 RUNNING DETECTOR AGENT ---")
    
    # 1. Get the raw event from the state
    event_data = state['raw_event']
    
    # 2. Initialize the LLM and Prompt
    # We create a "chain" that automatically formats the output as JSON
    llm_with_tools = get_detector_llm().with_structured_output(DetectionResult)
    prompt = get_detector_prompt()
    chain = prompt | llm_with_tools
    
    # 3. Invoke the chain
    try:
        result: DetectionResult = chain.invoke({
            "event_data": json.dumps(event_data, indent=2)
        })
        
        print(f"  Analysis: {result.analysis}")
        print(f"  Is Threat: {result.is_threat}")
        print(f"  Severity: {result.severity}")
        
        # 4. Update the state
        analysis_summary = (
            f"DETECTION: {result.analysis} "
            f"(Severity: {result.severity})"
        )
        
        return {
            "analysis": analysis_summary,
            "next_node": "investigate" if result.is_threat else "false_positive"
        }

    except Exception as e:
        print(f"  Error during detection: {e}")
        return {
            "analysis": "Error during detection. Defaulting to investigation.",
            "next_node": "investigate" # Fail-safe: always investigate if analysis fails
        }