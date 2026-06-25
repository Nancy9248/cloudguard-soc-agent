"""
Threat Explanation Agent

This agent is responsible for:
1. Taking the list of flagged events from the CloudTrail Analyst Agent.
2. For each flagged event, using Gemini to generate a plain-English explanation of why the event is dangerous and what an attacker could do.
3. Providing a local rule-based fallback if the Gemini API is rate-limited or exhausted.
"""

import sys
import os
import json
import time

# Add the project root directory to the Python path so imports work when running this script directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pydantic import BaseModel, Field
from typing import List, Dict
from google import genai
from google.genai import types

# Import the Analyst Agent so we can run our standalone test block at the bottom
from agents.cloudtrail_analyst import analyze_logs

# Define a Pydantic model to structure the threat explanation output from Gemini.
class ThreatExplanation(BaseModel):
    why_dangerous: str = Field(description="A plain-English explanation of why this activity is dangerous, written for a non-technical reader.")
    attacker_capabilities: str = Field(description="A plain-English description of what an attacker could do with this level of access or permissions.")

def local_fallback_explain(flagged_event: Dict) -> Dict:
    """
    A simple rule-based threat explanation engine used as a fallback if the Gemini API
    is unavailable (e.g., daily request quota exceeded).
    """
    event = flagged_event.get("event", {})
    event_name = event.get("eventName", "")
    user_identity = event.get("userIdentity", {})
    user_name = user_identity.get("userName") or user_identity.get("type", "UnknownUser")
    
    # Check for specific event types and provide preset, easy-to-understand explanations
    if event_name == "ConsoleLogin" and user_identity.get("type") == "Root":
        return {
            "why_dangerous": "Logging into the root (master) account is highly discouraged for daily tasks because it has unrestricted power over the entire AWS environment. If this account is compromised, the attacker has complete control.",
            "attacker_capabilities": "An attacker with root access can delete all backups, shut down servers, steal sensitive client data, and create massive unauthorized bills."
        }
    elif event_name == "PutUserPolicy":
        return {
            "why_dangerous": f"The user '{user_name}' attached a policy that grants full administrative access. In security terms, this is called 'privilege escalation', where someone gives themselves more power than they should have.",
            "attacker_capabilities": "An attacker using this account could read, modify, or delete any resource in the cloud network, effectively locking out legitimate administrators."
        }
    elif event_name == "DeleteSecurityGroup":
        return {
            "why_dangerous": f"A security group acts as a virtual firewall controlling network access. Deleting it is dangerous because it can suddenly expose internal databases and servers to the public internet, or disrupt communication.",
            "attacker_capabilities": "An attacker could destroy network security boundaries to gain direct access to private systems, install malware, or disrupt critical business systems."
        }
        
    # Catch-all fallback explanation
    reason = flagged_event.get("reason", "suspicious activity")
    return {
        "why_dangerous": f"This action was flagged as suspicious ({reason}). Unexpected configurations or actions can indicate that an account is being misused or has been compromised by an external party.",
        "attacker_capabilities": "Depending on the action, an attacker could exploit this configuration to gain deeper access, monitor network traffic, or modify settings without permission."
    }

def explain_threats(flagged_events: List[Dict]) -> List[Dict]:
    """
    Takes flagged events and adds plain-English explanations of the security risks.
    
    Args:
        flagged_events (List[Dict]): List of dictionaries from the Analyst Agent.
        
    Returns:
        List[Dict]: The updated list of flagged events, where each entry now includes:
                    - 'why_dangerous': Plain-English threat explanation.
                    - 'attacker_capabilities': Description of potential attacker actions.
    """
    # If no events were flagged, we have nothing to explain!
    if not flagged_events:
        print("[Threat Explainer] No flagged events to explain.")
        return []

    # 1. Verify GEMINI_API_KEY environment variable is set.
    if "GEMINI_API_KEY" not in os.environ:
        raise ValueError(
            "Error: GEMINI_API_KEY environment variable is not set.\n"
            "Please set it in your environment before running."
        )

    print(f"[Threat Explainer] Generating explanations for {len(flagged_events)} flagged event(s)...")
    
    # 2. Initialize the Gemini API client
    client = genai.Client()
    
    explained_events = []
    use_fallback_for_all = False
    
    # 3. Process each event
    for index, flagged in enumerate(flagged_events, start=1):
        event = flagged.get("event", {})
        event_name = event.get("eventName", "UnknownEvent")
        severity = flagged.get("severity", "medium")
        reason = flagged.get("reason", "Suspicious activity detected.")
        
        print(f"  [{index}/{len(flagged_events)}] Explaining threat for: {event_name} (Severity: {severity})...")
        
        # If the API quota is already known to be exhausted, use the fallback directly
        if use_fallback_for_all:
            print("    -> API quota exhausted. Using local fallback explanation...")
            fallback_res = local_fallback_explain(flagged)
            explained_events.append({
                **flagged,
                "why_dangerous": fallback_res["why_dangerous"],
                "attacker_capabilities": fallback_res["attacker_capabilities"]
            })
            continue

        # Construct prompt for Gemini to explain the threat
        prompt = f"""
        You are a Cloud Security Operations Center (SOC) Analyst explaining security threats to non-technical executives.
        Explain the security risk of the following flagged AWS CloudTrail event in plain English.
        
        Flagged Event Details:
        - Event Name: {event_name}
        - Severity: {severity}
        - Flagged Reason: {reason}
        
        Full Event Data:
        {json.dumps(event, indent=2)}
        
        Your response must contain:
        1. 'why_dangerous': Explain why this event is dangerous, in very simple, plain English, using clear analogies if helpful. Do not use jargon.
        2. 'attacker_capabilities': Explain what an attacker could do now if they compromised this account/resource.
        """
        
        # Define retry configuration to handle rate limits and service unavailability
        max_retries = 3
        backoff_seconds = 3
        api_failed = False
        
        for attempt in range(1, max_retries + 1):
            try:
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=ThreatExplanation,
                        temperature=0.2,
                    ),
                )
                
                # Parse structured JSON response
                explanation_data = json.loads(response.text)
                why_dangerous = explanation_data.get("why_dangerous")
                attacker_capabilities = explanation_data.get("attacker_capabilities")
                
                explained_events.append({
                    **flagged,
                    "why_dangerous": why_dangerous,
                    "attacker_capabilities": attacker_capabilities
                })
                print("    -> Explanation generated successfully via Gemini API.")
                break
                
            except Exception as e:
                error_msg = str(e)
                if ("429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or 
                    "503" in error_msg or "UNAVAILABLE" in error_msg):
                    
                    # Handle daily quota exhaustion directly
                    if "limit: 20" in error_msg or "limit: 0" in error_msg:
                        print("    -> [Warning] Gemini daily API quota reached! Switching to local fallback explanations...")
                        use_fallback_for_all = True
                        api_failed = True
                        break
                        
                    if attempt < max_retries:
                        print(f"    -> API rate limit or high demand (attempt {attempt}/{max_retries}). Retrying in {backoff_seconds}s...")
                        time.sleep(backoff_seconds)
                        backoff_seconds *= 2
                    else:
                        print("    -> API retries exhausted. Using local fallback explanations...")
                        api_failed = True
                else:
                    print(f"    -> Error generating explanation: {e}. Using local fallback explanations...")
                    api_failed = True
                    break
        
        # If API failed, run fallback
        if api_failed:
            fallback_res = local_fallback_explain(flagged)
            explained_events.append({
                **flagged,
                "why_dangerous": fallback_res["why_dangerous"],
                "attacker_capabilities": fallback_res["attacker_capabilities"]
            })
            
    print("[Threat Explainer] Finished threat explanations.")
    return explained_events

# Small test block to run both Analyst and Explainer agents standalone
if __name__ == "__main__":
    # Check if key is set before running
    if "GEMINI_API_KEY" not in os.environ:
        print("WARNING: GEMINI_API_KEY is not set. Standalone test will fail.")
        print("To run, set it in your command prompt or terminal first.")
        print('Example: $env:GEMINI_API_KEY="AIzaSy..."')
    else:
        print("--- STARTING AGENT PIPELINE INTEGRATION TEST ---")
        test_log_path = os.path.join("data", "sample_cloudtrail_logs.json")
        
        # Run Agent 1 (Analyst)
        flagged_results = analyze_logs(test_log_path)
        
        # Run Agent 2 (Threat Explainer)
        explained_results = explain_threats(flagged_results)
        
        print("\n=== DETAILED THREAT EXPLANATIONS ===")
        for idx, result in enumerate(explained_results, start=1):
            evt = result["event"]
            user_id = evt.get("userIdentity", {})
            user_name = user_id.get("userName") or user_id.get("type", "root")
            
            print(f"\n[{idx}] Threat: {evt.get('eventName')} by {user_name} (Severity: {result['severity'].upper()})")
            print(f"    Reason Flagged:  {result['reason']}")
            print(f"    Why Dangerous:   {result['why_dangerous']}")
            print(f"    Attacker Can Do: {result['attacker_capabilities']}")
