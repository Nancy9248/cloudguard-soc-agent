# CloudGuard - AI SOC Agent

### *An automated, multi-agent AI system that translates raw cloud audit logs into actionable security insights and executive intelligence.*

---

## 1. Problem Statement
Modern businesses generate millions of cloud activity logs every single day. Manually reviewing these logs is extremely slow, tedious, and highly prone to human error, often allowing critical threats to slip through unnoticed. For small-to-medium enterprises and lean security teams, this delay in threat detection and explanation represents a massive vulnerability, potentially leading to data breaches, compliance violations, and catastrophic financial loss.

## 2. Solution Overview
**CloudGuard** solves this challenge by orchestrating a sequential, four-agent AI pipeline. Instead of relying on manual analysis, the system automatically ingests raw AWS CloudTrail logs, flags security anomalies, explains the threats in non-technical business terms, suggests prioritized step-by-step remediation actions, and compiles everything into a clean executive report. 

## 3. Architecture
The pipeline consists of four specialized agents executing in sequence:

```
[ Raw CloudTrail Logs ]
          │
          ▼
┌─────────────────────────────────┐
│   1. CloudTrail Analyst Agent   │ ──► Parses raw JSON logs and flags security anomalies.
└─────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────┐
│   2. Threat Explanation Agent   │ ──► Explains the risk of each flagged event in plain English.
└─────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────┐
│      3. Remediation Agent       │ ──► Recommends prioritized, actionable security fixes.
└─────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────┐
│   4. Executive Report Agent     │ ──► Compiles findings into a professional, executive summary.
└─────────────────────────────────┘
          │
          ▼
[ output/executive_report.txt ]
```

1. **CloudTrail Analyst Agent**: Automatically parses raw, complex JSON logs, evaluates security postures, and flags suspicious events (such as root console logins, privilege escalations, or firewall deletions).
2. **Threat Explanation Agent**: Translates technical log data into clear, non-technical explanations of why the activity is dangerous and what an attacker could do with that access.
3. **Remediation Agent**: Recommends 2-3 specific security fixes for each threat, prioritized logically by urgency (`IMMEDIATE` vs `HIGH` vs `MEDIUM`).
4. **Executive Report Agent**: Synthesizes the findings and remediation steps into a professional text-based summary designed for managers and C-level executives.

## 4. Tech Stack
*   **Language**: Python 3.10+
*   **AI Engine**: Google Gemini API (`gemini-2.5-flash` for high-performance structured reasoning)
*   **Orchestration**: Custom multi-agent pipeline using Google Gen AI SDK concepts
*   **Development & Tooling**: Antigravity agentic framework, Pydantic (Structured Outputs), and python-dotenv

## 5. Setup & Installation

Follow these steps to run CloudGuard locally on your system:

### 1. Clone the Repository
```bash
git clone https://github.com/Nancy9248/cloudguard-soc-agent.git
cd cloudguard-soc-agent
```

### 2. Install Dependencies
Install the required packages, including the official Google Gen AI SDK:
```bash
pip install -r requirements.txt
```

### 3. Configure the Environment
Copy the example environment configuration:
```bash
copy .env.example .env
```
Open the newly created `.env` file and insert your actual Google Gemini API key:
```text
GEMINI_API_KEY=AIzaSyYourActualAPIKeyHere
```
*Note: If you do not have a key, you can obtain one for free from [Google AI Studio](https://aistudio.google.com/).*

### 4. Run the Pipeline
Execute the main orchestrator script to run the full end-to-end agent chain:
```bash
python main.py
```

## 6. Sample Output
Running the pipeline processes the log events and automatically generates a comprehensive text report saved in the project directory at:
*   [output/executive_report.txt](file:///c:/Users/Tarushi%20Tapaswy/OneDrive/Desktop/cloudguard-soc-agent/output/executive_report.txt)

This report details overall risk summaries, detected security issues with severity levels, and prioritized remediation actions (e.g., enabling root MFA, revoking administrative policies) written in polished, executive-friendly language.

## 7. Note on Reliability (Local Fallback Mode)
CloudGuard is designed with enterprise-grade resilience. If the Gemini API reaches its free-tier daily request quota limit or encounters transient network errors, the pipeline does not crash. Instead, each agent automatically falls back to a **Local Rule-Based Engine**. The local fallback scans the logs, flags threats, provides plain-English risk explanations, and recommends fixes entirely offline—guaranteeing 100% pipeline uptime under any conditions.

## 8. Future Improvements
*   **Live Cloud Integration**: Integrate directly with AWS EventBridge, S3, or Kinesis to analyze CloudTrail logs in near real-time.
*   **Active Remediation**: Implement automated one-click remediation playbooks using AWS SDK (Boto3) to automatically disable compromised keys or isolate instances.
*   **Security Dashboard UI**: Build a responsive web-based dashboard (using React or Streamlit) to visualize threats, log metrics, and security posture trends over time.
