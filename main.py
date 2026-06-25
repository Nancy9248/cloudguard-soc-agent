"""
AI SOC Agent - Main Orchestrator

This script coordinates the workflow across the four agents:
1. CloudTrail Analyst Agent: Flags suspicious events.
2. Threat Explanation Agent: Explains the risks.
3. Remediation Agent: Recommends fixes.
4. Executive Report Agent: Compiles the final security report.
"""

import os
import sys

# Add the project root directory to the Python path so imports work when running this script directly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.cloudtrail_analyst import analyze_logs
from agents.threat_explanation import explain_threats
from agents.remediation import suggest_remediations
from agents.executive_report import generate_report

def main():
    print("==================================================")
    print("Starting AI SOC Agent Orchestration Pipeline")
    print("==================================================")
    
    # 1. Define the path to our sample CloudTrail log data
    log_file_path = os.path.join("data", "sample_cloudtrail_logs.json")
    
    # 2. Step 1: Run the CloudTrail Analyst Agent to scan logs and flag suspicious activities
    print("\n[Step 1/4] Running CloudTrail Analyst Agent...")
    flagged_events = analyze_logs(log_file_path)
    print(f"-> Completed. Flagged {len(flagged_events)} suspicious event(s).")
    
    # 3. Step 2: Pass the flagged events to the Threat Explanation Agent to translate them into plain English
    print("\n[Step 2/4] Running Threat Explanation Agent...")
    explained_events = explain_threats(flagged_events)
    print("-> Completed. Explanations generated for all flagged events.")
    
    # 4. Step 3: Pass the threat explanations to the Remediation Agent to get step-by-step action items
    print("\n[Step 3/4] Running Remediation Agent...")
    remediated_events = suggest_remediations(explained_events)
    print("-> Completed. Actionable remediation steps generated.")
    
    # 5. Step 4: Pass the final compiled findings to the Executive Report Agent to generate the summary
    # Note: The Executive Report Agent will automatically write the output to output/executive_report.txt.
    print("\n[Step 4/4] Running Executive Report Agent...")
    report_content = generate_report(remediated_events)
    
    print("\n==================================================")
    print("Pipeline complete! Report saved to output/executive_report.txt")
    print("==================================================")
    
    # Print a preview of the report to the console for quick verification
    print("\n--- REPORT PREVIEW ---")
    preview_lines = report_content.splitlines()[:18]
    print("\n".join(preview_lines))
    if len(report_content.splitlines()) > 18:
        print("\n... [Remaining content saved to file] ...")

if __name__ == "__main__":
    main()
