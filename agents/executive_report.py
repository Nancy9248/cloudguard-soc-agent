"""
Executive Report Agent

This agent is responsible for:
1. Taking the compiled security data (events, threat explanations, and remediation steps) as input.
2. Generating a clean, professional security report written in confident, business-friendly language for non-technical executives.
3. Saving the final report as a text file at 'output/executive_report.txt'.
4. Providing a local template-based fallback if the Gemini API is rate-limited or exhausted.
"""

import sys
import os
import json
import time
from datetime import datetime
from pydantic import BaseModel, Field
from typing import List, Dict
from google import genai
from google.genai import types

# Add the project root directory to the Python path so imports work when running this script directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import previous agents to run the full end-to-end pipeline in the test block
from agents.remediation import suggest_remediations, explain_threats, analyze_logs

# Define Pydantic model to structure report content from Gemini.
class ExecutiveReport(BaseModel):
    report_text: str = Field(description="The complete executive security report formatted as plain text, using the specified sections.")

def local_fallback_report(remediated_events: List[Dict]) -> str:
    """
    A template-based report generator used as a fallback if the Gemini API
    is unavailable (e.g., daily request quota exceeded).
    """
    current_date = datetime.now().strftime("%Y-%m-%d")
    
    total_issues = len(remediated_events)
    critical_count = sum(1 for e in remediated_events if e.get("severity", "").lower() == "critical")
    high_count = sum(1 for e in remediated_events if e.get("severity", "").lower() == "high")
    medium_count = sum(1 for e in remediated_events if e.get("severity", "").lower() == "medium")
    low_count = sum(1 for e in remediated_events if e.get("severity", "").lower() == "low")
    
    # Section 1: Title and Date
    report = f"============================================================\n"
    report += f"EXECUTIVE SECURITY AUDIT REPORT\n"
    report += f"Date: {current_date}\n"
    report += f"Classification: Internal Use Only\n"
    report += f"============================================================\n\n"
    
    # Section 2: Overall Risk Summary
    report += "1. OVERALL RISK SUMMARY\n"
    report += "------------------------------------------------------------\n"
    if total_issues == 0:
        report += "Our security auditing tools completed a scan of our AWS CloudTrail activity logs today.\n"
        report += "Status: SECURE. No suspicious or unauthorized events were detected.\n\n"
    else:
        report += f"Today's automated security audit analyzed CloudTrail log records and identified\n"
        report += f"a total of {total_issues} security issues that require management attention:\n"
        summary_details = []
        if critical_count > 0:
            summary_details.append(f"{critical_count} CRITICAL priority threat(s)")
        if high_count > 0:
            summary_details.append(f"{high_count} HIGH priority threat(s)")
        if medium_count > 0:
            summary_details.append(f"{medium_count} MEDIUM priority threat(s)")
        if low_count > 0:
            summary_details.append(f"{low_count} LOW priority threat(s)")
            
        report += f" - " + ", ".join(summary_details) + ".\n"
        report += "Action is required to mitigate these vulnerabilities and protect our cloud infrastructure.\n\n"
        
    # Section 3: List of Issues
    report += "2. DETECTED SECURITY ISSUES\n"
    report += "------------------------------------------------------------\n"
    if total_issues == 0:
        report += "No issues found.\n\n"
    else:
        report += f"{'Severity':<12} | {'Event / Action':<22} | {'Risk Summary'}\n"
        report += f"{'-'*12}-+-{'-'*22}-+-{'-'*30}\n"
        for item in remediated_events:
            severity = item.get("severity", "MEDIUM").upper()
            event_name = item.get("event", {}).get("eventName", "Unknown")
            reason = item.get("reason", "Suspicious activity detected.")
            # Remove (Local Fallback Rule) from reason for the executive report
            reason = reason.replace(" (Local Fallback Rule)", "")
            if len(reason) > 40:
                reason = reason[:37] + "..."
            report += f"{severity:<12} | {event_name:<22} | {reason}\n"
        report += "\n"
        
    # Section 4: Recommended Next Steps, prioritized
    report += "3. RECOMMENDED ACTIONS AND NEXT STEPS\n"
    report += "------------------------------------------------------------\n"
    if total_issues == 0:
        report += "Maintain regular monitoring activities and ensure security logging remains active.\n"
    else:
        # Collect and group remediations by urgency
        all_remediations = []
        for item in remediated_events:
            event_name = item.get("event", {}).get("eventName", "Unknown")
            for rem in item.get("remediations", []):
                all_remediations.append({
                    "urgency": rem.get("urgency", "MEDIUM").upper(),
                    "action": rem.get("action", "Remediation step"),
                    "description": rem.get("description", ""),
                    "event": event_name
                })
                
        # Sort so IMMEDIATE is first, then HIGH, then MEDIUM, then LOW
        urgency_order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_remediations.sort(key=lambda x: urgency_order.get(x["urgency"], 4))
        
        for idx, step in enumerate(all_remediations, start=1):
            report += f"[{idx}] URGENCY: {step['urgency']}\n"
            report += f"    Action: {step['action']}\n"
            report += f"    Impact: Addresses threat associated with {step['event']}\n"
            report += f"    Details: {step['description']}\n\n"
            
    report += "============================================================\n"
    report += "Report generated locally via template fallback.\n"
    return report

def generate_report(remediated_events: List[Dict]) -> str:
    """
    Compiles findings, threat explanations, and remediations into one final summary report.
    Saves the final report to 'output/executive_report.txt'.
    
    Args:
        remediated_events (List[Dict]): Fully annotated list of events.
        
    Returns:
        str: The final report string.
    """
    # 1. Check GEMINI_API_KEY environment variable
    if "GEMINI_API_KEY" not in os.environ:
        raise ValueError(
            "Error: GEMINI_API_KEY environment variable is not set.\n"
            "Please set it in your environment before running."
        )

    print("[Executive Report Agent] Compiling final executive report...")
    
    # 2. Check if there are any events to report. If none, we can generate a short clean green report.
    if not remediated_events:
        print("[Executive Report Agent] No security concerns to report.")
        report_content = local_fallback_report([])
        
        # Save report
        os.makedirs("output", exist_ok=True)
        report_file_path = os.path.join("output", "executive_report.txt")
        with open(report_file_path, "w") as f:
            f.write(report_content)
        return report_content

    # 3. Initialize Gemini API Client
    client = genai.Client()
    
    report_content = ""
    api_failed = False
    
    # Construct a prompt telling Gemini to compile all compiled facts into a polished business text document.
    prompt = f"""
    You are an expert Chief Information Security Officer (CISO).
    Generate a clean, professional, and comprehensive Executive Security Audit Report based on the following security events, threat explanations, and proposed fixes.
    
    The report MUST be written for a non-technical manager or executive. Use simple, confident, business-appropriate language. Avoid technical jargon.
    
    Structure the report with exactly these sections:
    1. Title and Date (formatted clearly)
    2. Overall Risk Summary (explain the scan results, number of issues found, and their priority in business terms)
    3. Detected Security Issues (present the issues in a list, including their severity, why they are dangerous, and the risk/impact on operations)
    4. Recommended Next Steps (a prioritized action list based on urgency, describing what actions management should authorize immediately vs soon)
    
    Input Data:
    {json.dumps(remediated_events, indent=2)}
    """
    
    max_retries = 3
    backoff_seconds = 3
    
    for attempt in range(1, max_retries + 1):
        try:
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ExecutiveReport,
                    temperature=0.3,
                ),
            )
            
            report_data = json.loads(response.text)
            report_content = report_data.get("report_text", "")
            print("    -> Executive report generated successfully via Gemini API.")
            break
            
        except Exception as e:
            error_msg = str(e)
            if ("429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or 
                "503" in error_msg or "UNAVAILABLE" in error_msg):
                
                if "limit: 20" in error_msg or "limit: 0" in error_msg:
                    print("    -> [Warning] Gemini daily API quota reached! Switching to local fallback report generator...")
                    api_failed = True
                    break
                    
                if attempt < max_retries:
                    print(f"    -> API rate limit or high demand (attempt {attempt}/{max_retries}). Retrying in {backoff_seconds}s...")
                    time.sleep(backoff_seconds)
                    backoff_seconds *= 2
                else:
                    print("    -> API retries exhausted. Using local fallback report generator...")
                    api_failed = True
            else:
                print(f"    -> Error generating report: {e}. Using local fallback report generator...")
                api_failed = True
                break
                
    if api_failed or not report_content:
        report_content = local_fallback_report(remediated_events)
        
    # 4. Save the final report text to 'output/executive_report.txt'
    os.makedirs("output", exist_ok=True)
    report_file_path = os.path.join("output", "executive_report.txt")
    with open(report_file_path, "w") as f:
        f.write(report_content)
        
    print(f"[Executive Report Agent] Report saved successfully to {report_file_path}")
    return report_content

# Small test block to run the FULL pipeline end-to-end standalone
if __name__ == "__main__":
    if "GEMINI_API_KEY" not in os.environ:
        print("WARNING: GEMINI_API_KEY is not set. Standalone test will fail.")
        print("To run, set it in your command prompt or terminal first.")
        print('Example: $env:GEMINI_API_KEY="AIzaSy..."')
    else:
        print("--- RUNNING FULL END-TO-END AGENT PIPELINE TEST ---")
        test_log_path = os.path.join("data", "sample_cloudtrail_logs.json")
        
        # Step 1: Run CloudTrail Analyst
        flagged_results = analyze_logs(test_log_path)
        
        # Step 2: Run Threat Explainer
        explained_results = explain_threats(flagged_results)
        
        # Step 3: Run Remediation Specialist
        remediated_results = suggest_remediations(explained_results)
        
        # Step 4: Run Executive Report Agent
        report = generate_report(remediated_results)
        
        print("\n=== GENERATED EXECUTIVE REPORT ===")
        print(report)
