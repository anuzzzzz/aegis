import json
from pathlib import Path
from dotenv import load_dotenv
from .graph import create_agent_graph

def run_test():
    """
    Loads synthetic data and runs it through the agent graph.
    """
    print("--- 🚀 INITIALIZING AEGIS AGENT GRAPH ---")
    
    # --- Load .env variables (like AWS keys) ---
    # This assumes your .env file is in the root 'aegis/' directory
    env_path = Path(__file__).parent.parent.parent / ".env"
    load_dotenv(dotenv_path=env_path)
    
    # --- Load Synthetic Data ---
    # We'll load one event from your GuardDuty findings file.
    try:
        data_path = Path(__file__).parent.parent.parent / "data" / "synthetic_guardduty_findings.json"
        with open(data_path, 'r') as f:
            test_data = json.load(f)
        
        # Get the first finding as our test event
        # You can loop through `test_data` to test all events
        initial_event = test_data[0] 
        print(f"--- 📥 LOADED TEST EVENT (ID: {initial_event.get('Id')}) ---")
        print(json.dumps(initial_event, indent=2))
        
    except FileNotFoundError:
        print(f"Error: Could not find data file at {data_path}")
        print("Please ensure 'data/synthetic_guardduty_findings.json' exists.")
        return
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error reading or parsing data file: {e}")
        return
    except IndexError:
        print("Error: The synthetic data file is empty.")
        return

    # --- Compile and Run Graph ---
    app = create_agent_graph()
    
    # This is the initial input to the graph.
    # It must match the structure of AgentState
    inputs = {
        "raw_event": initial_event,
    }
    
    print("\n--- ⚡ EXECUTING GRAPH ---")
    
    # `stream()` runs the graph and shows the output of each step
    for step in app.stream(inputs):
        step_name = list(step.keys())[0]
        step_output = list(step.values())[0]
        
        print(f"\n--- Output from: {step_name} ---")
        if 'analysis' in step_output:
            print(step_output['analysis'])
        else:
            print("  (No 'analysis' in final output)")

    print("\n--- ✅ GRAPH EXECUTION COMPLETE ---")

if __name__ == "__main__":
    run_test()