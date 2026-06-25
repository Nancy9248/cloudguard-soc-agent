"""
Remediation Agent

This agent is responsible for:
1. Taking the threat explanations list from the Threat Explanation Agent.
2. For each flagged event, using Gemini to suggest 2-3 specific, prioritized remediation steps.
3. Handling API rate limits (429) and transient errors (503) using retries and a local fallback template.
"""

import sys
import os
import json
import time
from pydantic import BaseModel, Field
from typing import List, Dict
from google import genai
from google.genai import types

# Add the project root directory to the Python path so imports work when running this script directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the Threat Explanation Agent (which imports Analyst) to run the full chain in the test block
from agents.threat_explanation import explain_threats, analyze_logs

# Define Pydantic models to structure the remediation output from Gemini.
class RemediationStep(BaseModel):
    urgency: str = Field(description="The urgency level (e.g., 'IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW').")
    action: str = Field(description="The specific action to take to fix or prevent the security issue.")
    description: str = Field(description="A brief description of how to perform the action and why it helps.")

class EventRemediation(BaseModel):
    remediations: List[RemediationStep] = Field(description="List of 2-3 prioritized remediation steps.")

def local_fallback_remediate(flagged_event: Dict) -> List[Dict]:
    """
    A simple rule-based remediation engine used as a fallback if the Gemini API
    is unavailable (e.g., daily request quota exceeded).
    """
    event = flagged_event.get("event", {})
    event_name = event.get("eventName", "")
    user_identity = event.get("userIdentity", {})
    user_name = user_identity.get("userName") or user_identity.get("type", "UnknownUser")
    
    if event_name == "ConsoleLogin" and user_identity.get("type") == "Root":
        return [
            {
                "urgency": "IMMEDIATE",
                "action": "Enable Multi-Factor Authentication (MFA) on the Root Account.",
                "description": "Log into the root account, navigate to IAM Security Credentials, and set up a hardware or virtual MFA device to prevent unauthorized logins."
            },
            {
                "urgency": "IMMEDIATE",
                "action": "Change the Root Account password.",
                "description": "If an unauthorized login occurred, change the root password immediately using a strong, unique, randomly-generated passphrase."
            },
            {
                "urgency": "HIGH",
                "action": "Avoid using the Root account for daily operations.",
                "description": "Create individual IAM users with limited administrative privileges and lock away the root credentials."
            }
        ]
    elif event_name == "PutUserPolicy":
        return [
            {
                "urgency": "IMMEDIATE",
                "action": "Revoke the wildcard administrative policy.",
                "description": f"Navigate to the IAM policy settings for user '{user_name}' and remove the custom policy granting '*:*' full administrative access."
            },
            {
                "urgency": "IMMEDIATE",
                "action": "Audit and rotate the credentials of this user.",
                "description": f"Temporarily deactivate the access keys and console password of '{user_name}' until the owner of the account is verified."
            },
            {
                "urgency": "MEDIUM",
                "action": "Implement IAM Permissions Boundaries.",
                "description": "Use permissions boundaries or Service Control Policies (SCPs) to restrict users from escalating their own privileges in the future."
            }
        ]
    elif event_name == "DeleteSecurityGroup":
        return [
            {
                "urgency": "IMMEDIATE",
                "action": "Verify and restore missing network access rules.",
                "description": "Confirm if any resources were broken by the security group deletion. Recreate the security group and re-apply firewall rules if needed."
            },
            {
                "urgency": "HIGH",
                "action": "Investigate the IAM user who performed the deletion.",
                "description": f"Check if user '{user_name}' acted intentionally. If the activity was unauthorized, immediately revoke their active sessions and rotate access keys."
            },
            {
                "urgency": "MEDIUM",
                "action": "Restrict Security Group deletion permissions.",
                "description": "Update IAM policies to only allow senior administrators or automation systems to delete critical networking resources."
            }
        ]
        
    # Catch-all fallback remediation steps
    return [
        {
            "urgency": "IMMEDIATE",
            "action": "Investigate active sessions and credentials.",
            "description": "Rotate access credentials (passwords, API keys) for the associated user and terminate any active sessions immediately."
        },
        {
            "urgency": "HIGH",
            "action": "Roll back the suspicious configuration change.",
            "description": "Revert the resource status or configuration to its previous secure state using backups or configuration history."
        }
    ]

def suggest_remediations(explained_events: List[Dict]) -> List[Dict]:
    """
    Takes threat explanations and generates prioritized remediation steps.
    
    Args:
        explained_events (List[Dict]): List of events from the Threat Explanation Agent.
        
    Returns:
        List[Dict]: The updated list of events, where each entry now includes:
                    - 'remediations': A list of dicts containing 'urgency', 'action', and 'description'.
    """
    if not explained_events:
        print("[Remediation Agent] No events to remediate.")
        return []

    # 1. Verify GEMINI_API_KEY environment variable is set
    if "GEMINI_API_KEY" not in os.environ:
        raise ValueError(
            "Error: GEMINI_API_KEY environment variable is not set.\n"
            "Please set it in your environment before running."
        )

    print(f"[Remediation Agent] Generating remediations for {len(explained_events)} event(s)...")
    
    # 2. Initialize Gemini API Client
    client = genai.Client()
    
    remediated_events = []
    use_fallback_for_all = False
    
    # 3. Process each event
    for index, flagged in enumerate(explained_events, start=1):
        event = flagged.get("event", {})
        event_name = event.get("eventName", "UnknownEvent")
        severity = flagged.get("severity", "medium")
        why_dangerous = flagged.get("why_dangerous", "Suspicious activity detected.")
        attacker_capabilities = flagged.get("attacker_capabilities", "Potential unauthorized actions.")
        
        print(f"  [{index}/{len(explained_events)}] Generating fixes for: {event_name}...")
        
        if use_fallback_for_all:
            print("    -> API quota exhausted. Using local fallback remediation...")
            fallback_res = local_fallback_remediate(flagged)
            remediated_events.append({
                **flagged,
                "remediations": fallback_res
            })
            continue

        # Construct prompt for Gemini to suggest remediations
        prompt = f"""
        You are a Cloud Security Operations Center (SOC) Response Specialist.
        Provide 2-3 specific, prioritized, and actionable remediation steps to address the following threat:
        
        Event Details:
        - Event Name: {event_name}
        - Severity: {severity}
        - Why Dangerous: {why_dangerous}
        - Attacker Capabilities: {attacker_capabilities}
        
        Full Event Data:
        {json.dumps(event, indent=2)}
        
        Your response must conform to the EventRemediation structure containing:
        - 'remediations': A list of steps, each with:
          - 'urgency': How quickly to act ('IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW').
          - 'action': What concrete action to take (e.g., 'Revoke access key X').
          - 'description': Brief explanation of how to perform the action and why.
        """
        
        # Define retry configuration
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
                        response_schema=EventRemediation,
                        temperature=0.2,
                    ),
                )
                
                # Parse structured JSON response
                remediation_data = json.loads(response.text)
                remediations = remediation_data.get("remediations", [])
                
                remediated_events.append({
                    **flagged,
                    "remediations": remediations
                })
                print("    -> Remediations generated successfully via Gemini API.")
                break
                
            except Exception as e:
                error_msg = str(e)
                if ("429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or 
                    "503" in error_msg or "UNAVAILABLE" in error_msg):
                    
                    if "limit: 20" in error_msg or "limit: 0" in error_msg:
                        print("    -> [Warning] Gemini daily API quota reached! Switching to local fallback remediations...")
                        use_fallback_for_all = True
                        api_failed = True
                        break
                        
                    if attempt < max_retries:
                        print(f"    -> API rate limit or high demand (attempt {attempt}/{max_retries}). Retrying in {backoff_seconds}s...")
                        time.sleep(backoff_seconds)
                        backoff_seconds *= 2
                    else:
                        print("    -> API retries exhausted. Using local fallback remediations...")
                        api_failed = True
                else:
                    print(f"    -> Error generating remediations: {e}. Using local fallback remediations...")
                    api_failed = True
                    break
                    
        if api_failed:
            fallback_res = local_fallback_remediate(flagged)
            remediated_events.append({
                **flagged,
                "remediations": fallback_res
            })
            
    print("[Remediation Agent] Finished remediation generation.")
    return remediated_events

# Small test block to run the entire chain standalone
if __name__ == "__main__":
    if "GEMINI_API_KEY" not in os.environ:
        print("WARNING: GEMINI_API_KEY is not set. Standalone test will fail.")
        print("To run, set it in your command prompt or terminal first.")
        print('Example: $env:GEMINI_API_KEY="AIzaSy..."')
    else:
        print("--- STARTING FULL PIPELINE INTEGRATION TEST ---")
        test_log_path = os.path.join("data", "sample_cloudtrail_logs.json")
        
        # Step 1: Run Agent 1 (Analyst)
        flagged_results = analyze_logs(test_log_path)
        
        # Step 2: Run Agent 2 (Threat Explainer)
        explained_results = explain_threats(flagged_results)
        
        # Step 3: Run Agent 3 (Remediation Specialist)
        remediated_results = suggest_remediations(explained_results)
        
        print("\n=== FINAL THREAT AND REMEDIATION DETAILS ===")
        for idx, result in enumerate(remediated_results, start=1):
            evt = result["event"]
            user_id = evt.get("userIdentity", {})
            user_name = user_id.get("userName") or user_id.get("type", "root")
            
            print(f"\n[{idx}] Threat: {evt.get('eventName')} by {user_name} (Severity: {result['severity'].upper()})")
            print(f"    Reason Flagged:  {result['reason']}")
            print(f"    Why Dangerous:   {result['why_dangerous']}")
            print(f"    Attacker Can Do: {result['attacker_capabilities']}")
            print(f"    Suggested Remediations:")
            for step in result["remediations"]:
                print(f"      - [{step['urgency']}] {step['action']}")
                print(f"        How: {step['description']}")
