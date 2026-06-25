"""
CloudTrail Analyst Agent

This agent is responsible for:
1. Loading and parsing AWS CloudTrail logs (JSON format).
2. For each event, calling the Gemini API to evaluate whether the activity is suspicious or normal.
3. Handling API rate limits (429) and transient errors (503) with automatic retries and backoff.
4. Falling back to a local rule-based scanner if the Gemini API is exhausted or unavailable.
5. If an event is flagged as suspicious, assigning it a severity level: low, medium, high, or critical.
6. Returning a clean Python list of flagged events, containing the original event, severity, and the reason.
"""

import os
import json
import time
from pydantic import BaseModel, Field
from typing import Literal, Optional, List
from google import genai
from google.genai import types

# Define a Pydantic model to enforce a structured response from Gemini.
# This ensures that Gemini always returns a clean JSON matching this exact structure,
# which makes our Python code robust and easy to parse.
class EventAnalysis(BaseModel):
    is_suspicious: bool = Field(description="True if the event represents suspicious, anomalous, or potentially risky activity. False otherwise.")
    severity: Optional[Literal["low", "medium", "high", "critical"]] = Field(
        default=None,
        description="The threat severity level (low, medium, high, critical). Only set this if is_suspicious is True."
    )
    reason: str = Field(description="A concise, one-line explanation in plain English of why the event is suspicious or why it is normal.")

def local_fallback_analyze(event: dict) -> dict:
    """
    A rule-based security scanner used as a fallback if the Gemini API
    is unavailable (e.g., daily request quota exceeded).
    """
    event_name = event.get("eventName", "")
    user_identity = event.get("userIdentity", {})
    user_name = user_identity.get("userName") or user_identity.get("type", "UnknownUser")
    
    # Rule 1: Root console login without MFA
    if event_name == "ConsoleLogin" and user_identity.get("type") == "Root":
        additional_data = event.get("additionalEventData", {})
        mfa_used = additional_data.get("MFAUsed")
        if mfa_used != "Yes":
            return {
                "is_suspicious": True,
                "severity": "critical",
                "reason": "Root account console login occurred without Multi-Factor Authentication (MFA), which is a critical security risk. (Local Fallback Rule)"
            }
            
    # Rule 2: PutUserPolicy granting admin permissions
    if event_name == "PutUserPolicy":
        request_params = event.get("requestParameters", {})
        policy_document = request_params.get("policyDocument", "")
        if '"Action":"*"' in policy_document or '"Resource":"*"' in policy_document:
            return {
                "is_suspicious": True,
                "severity": "critical",
                "reason": f"User '{user_name}' attached a policy allowing full access ('*'), indicating potential privilege escalation. (Local Fallback Rule)"
            }
            
    # Rule 3: Deletion of critical network security infrastructure
    if event_name == "DeleteSecurityGroup":
        return {
            "is_suspicious": True,
            "severity": "high",
            "reason": f"Destructive action 'DeleteSecurityGroup' performed by user '{user_name}', which could impact network access controls. (Local Fallback Rule)"
        }
        
    return {
        "is_suspicious": False,
        "severity": None,
        "reason": "Event matches normal operational pattern. (Local Fallback Rule)"
    }

def analyze_logs(log_file_path: str) -> List[dict]:
    """
    Reads AWS CloudTrail logs from a JSON file and uses Gemini to identify suspicious events.
    
    Args:
        log_file_path (str): Path to the sample CloudTrail logs JSON file.
        
    Returns:
        List[dict]: A list of flagged events. Each entry contains:
                    - 'event': The original CloudTrail event dictionary.
                    - 'severity': The threat level ('low', 'medium', 'high', 'critical').
                    - 'reason': A short explanation of why it was flagged.
    """
    # 1. Verify that the GEMINI_API_KEY environment variable is set.
    # The official SDK requires this key to authenticate requests.
    if "GEMINI_API_KEY" not in os.environ:
        raise ValueError(
            "Error: GEMINI_API_KEY environment variable is not set.\n"
            "Please set it in your environment. Example in Windows PowerShell:\n"
            '  $env:GEMINI_API_KEY="your_actual_api_key"'
        )
    
    # 2. Read the CloudTrail logs JSON file.
    if not os.path.exists(log_file_path):
        print(f"[CloudTrail Analyst] Error: File not found at {log_file_path}")
        return []
        
    print(f"[CloudTrail Analyst] Loading logs from {log_file_path}...")
    with open(log_file_path, "r") as f:
        log_data = json.load(f)
    
    # CloudTrail files store event records under the "Records" key
    events = log_data.get("Records", [])
    if not events:
        print("[CloudTrail Analyst] No events found in the 'Records' list.")
        return []
    
    print(f"[CloudTrail Analyst] Loaded {len(events)} events. Starting analysis...")
    
    # 3. Initialize the Google Gen AI client.
    client = genai.Client()
    
    flagged_events = []
    use_fallback_for_all = False
    
    # 4. Iterate and analyze each event using Gemini
    for index, event in enumerate(events, start=1):
        event_name = event.get("eventName", "UnknownEvent")
        user_identity = event.get("userIdentity", {})
        user_name = user_identity.get("userName") or user_identity.get("type", "UnknownUser")
        print(f"  [{index}/{len(events)}] Analyzing event: {event_name} by user: {user_name}...")
        
        # If we already detected that the API is fully exhausted, skip to fallback directly to save time
        if use_fallback_for_all:
            print("    -> API quota exhausted. Using local fallback rule...")
            fallback_res = local_fallback_analyze(event)
            if fallback_res["is_suspicious"]:
                print(f"    -> Flagged as SUSPICIOUS (Fallback)! Severity: {fallback_res['severity']}. Reason: {fallback_res['reason']}")
                flagged_events.append({
                    "event": event,
                    "severity": fallback_res["severity"],
                    "reason": fallback_res["reason"]
                })
            else:
                print(f"    -> Marked as Normal (Fallback). Reason: {fallback_res['reason']}")
            continue

        # Construct a detailed prompt for Gemini to guide its security analysis
        prompt = f"""
        You are an expert Cloud Security Operations Center (SOC) Analyst.
        Analyze the following AWS CloudTrail log event and determine if it represents suspicious, anomalous, or high-risk activity.
        
        Guidelines for classification:
        - Safe/Normal: Standard activities like listing resources (ListBuckets, DescribeInstances) or normal console logins with MFA.
        - Suspicious/Risky: 
          - Root account usage (especially console sign-in without MFA)
          - Privilege escalation attempts (like PutUserPolicy granting '*' permissions)
          - Unauthorized or anomalous deletions of infrastructure (like DeleteSecurityGroup)
          - Actions coming from unusual/untrusted IP ranges
        
        CloudTrail Event JSON:
        {json.dumps(event, indent=2)}
        """
        
        # Define retry configuration to handle rate limits (429) or spikes in demand (503)
        max_retries = 3
        backoff_seconds = 3
        api_failed = False
        
        for attempt in range(1, max_retries + 1):
            try:
                # Request analysis from Gemini using Structured Outputs
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=EventAnalysis,
                        temperature=0.1, # Lower temperature makes the model more consistent and predictable
                    ),
                )
                
                # Parse the structured JSON response from Gemini
                analysis_data = json.loads(response.text)
                is_suspicious = analysis_data.get("is_suspicious", False)
                severity = analysis_data.get("severity")
                reason = analysis_data.get("reason", "No reason provided.")
                
                if is_suspicious:
                    print(f"    -> Flagged as SUSPICIOUS! Severity: {severity}. Reason: {reason}")
                    flagged_events.append({
                        "event": event,
                        "severity": severity or "medium", # Default to medium if not specified
                        "reason": reason
                    })
                else:
                    print(f"    -> Marked as Normal. Reason: {reason}")
                
                # Successfully analyzed, break out of the retry loop
                break
                
            except Exception as e:
                error_msg = str(e)
                # Check for rate limiting (429) or service unavailable (503) errors
                if ("429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or 
                    "503" in error_msg or "UNAVAILABLE" in error_msg):
                    
                    # If it's a daily quota limit exhaustion (limit: 20 per day), wait won't help. 
                    # Trigger fallback immediately and set use_fallback_for_all to True.
                    if "limit: 20" in error_msg or "limit: 0" in error_msg:
                        print("    -> [Warning] Gemini daily API quota has been reached! Switching to local fallback rules...")
                        use_fallback_for_all = True
                        api_failed = True
                        break
                        
                    if attempt < max_retries:
                        print(f"    -> API rate limit or high demand (attempt {attempt}/{max_retries}). Retrying in {backoff_seconds}s...")
                        time.sleep(backoff_seconds)
                        backoff_seconds *= 2  # Double the backoff duration (exponential backoff)
                    else:
                        print("    -> API retries exhausted. Using local fallback rules...")
                        api_failed = True
                else:
                    print(f"    -> Error analyzing event {index}: {e}. Using local fallback rules...")
                    api_failed = True
                    break
        
        # If API failed on this event, run fallback
        if api_failed:
            fallback_res = local_fallback_analyze(event)
            if fallback_res["is_suspicious"]:
                print(f"    -> Flagged as SUSPICIOUS (Fallback)! Severity: {fallback_res['severity']}. Reason: {fallback_res['reason']}")
                flagged_events.append({
                    "event": event,
                    "severity": fallback_res["severity"],
                    "reason": fallback_res["reason"]
                })
            else:
                print(f"    -> Marked as Normal (Fallback). Reason: {fallback_res['reason']}")
            
    print(f"[CloudTrail Analyst] Finished analysis. Flagged {len(flagged_events)} out of {len(events)} events.")
    return flagged_events

# Small test block to run this module standalone
if __name__ == "__main__":
    # For local standalone testing
    test_log_path = os.path.join("data", "sample_cloudtrail_logs.json")
    
    # Check if key is set before running
    if "GEMINI_API_KEY" not in os.environ:
        print("WARNING: GEMINI_API_KEY is not set. Standalone test will fail.")
        print("To run, set it in your command prompt or terminal first.")
        print('Example: $env:GEMINI_API_KEY="AIzaSy..."')
    else:
        print("Running CloudTrail Analyst standalone test...")
        results = analyze_logs(test_log_path)
        
        print("\n=== FLAGGED EVENTS RESULTS ===")
        for idx, result in enumerate(results, start=1):
            evt = result["event"]
            user_id = evt.get("userIdentity", {})
            user_name = user_id.get("userName") or user_id.get("type", "root")
            print(f"\n[{idx}] Event: {evt.get('eventName')} (User: {user_name})")
            print(f"    Severity: {result['severity'].upper()}")
            print(f"    Reason:   {result['reason']}")
