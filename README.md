# 🛡️ SentinelAI — Security Alert Investigation Copilot

**An AI-assisted cybersecurity investigation tool that analyzes security logs, detects suspicious login patterns, and generates evidence-grounded investigation summaries.**

SentinelAI is a local web application built with Python, Streamlit, and Ollama. It helps users investigate selected security events through transparent rule-based detection, supporting log evidence, and AI-generated summaries.

> **Project Status:** Local V1 prototype
> **Primary Focus:** Defensive Cybersecurity + AI Engineering
> **Execution Mode:** Local application with a local LLM
> **Intended Use:** Synthetic or authorized security logs

---

## 📌 Table of Contents

1. [Project Overview](#-project-overview)
2. [Problem Statement](#-problem-statement)
3. [Project Objectives](#-project-objectives)
4. [Target Users](#-target-users)
5. [Key Features](#-key-features)
6. [Technology Stack](#-technology-stack)
7. [System Architecture](#-system-architecture)
8. [How SentinelAI Works](#-how-sentinelai-works)
9. [Detection Logic](#-detection-logic)
10. [AI Investigation Summary](#-ai-investigation-summary)
11. [AI Evidence Validation](#-ai-evidence-validation)
12. [Project Structure](#-project-structure)
13. [Installation and Setup](#-installation-and-setup)
14. [Running SentinelAI](#-running-sentinelai)
15. [Running Automated Tests](#-running-automated-tests)
16. [Sample Input Format](#-sample-input-format)
17. [Example Investigation Workflow](#-example-investigation-workflow)
18. [Security and Safety](#-security-and-safety)
19. [Current Limitations](#-current-limitations)
20. [Future Improvements](#-future-improvements)
21. [Learning Outcomes](#-learning-outcomes)
22. [Project Goals and Success Criteria](#-project-goals-and-success-criteria)
23. [Author](#-author)

---

## 🚀 Project Overview

Security analysts often need to inspect authentication logs to identify patterns that may require further investigation.

SentinelAI provides a local interface for uploading security logs, validating input data, detecting selected suspicious login patterns, reviewing supporting evidence, and generating an AI-assisted investigation summary.

The application combines two approaches:

* **Rule-based detection:** Identifies specific patterns using explicit detection logic.
* **AI-assisted investigation:** Uses a local language model to generate a readable summary that can help an analyst understand an alert.

SentinelAI also includes basic consistency checks to compare selected AI-generated claims against the available log evidence.

The application is designed to assist investigation, not to replace a security analyst.

## 🎯 Problem Statement

Security logs can contain many events, making it difficult for learners and analysts to identify activity that deserves closer inspection.

A suspicious authentication pattern may involve multiple failed login attempts followed by a successful login for the same username.

SentinelAI addresses this problem by:

* Validating uploaded security log data.
* Detecting a selected suspicious authentication pattern.
* Presenting the relevant events as supporting evidence.
* Generating an AI-assisted investigation summary.
* Checking selected claims against the evidence.
* Suggesting additional investigation steps.

An alert indicates a pattern that requires review. It does not independently prove that an account has been compromised.

## 🎯 Project Objectives

The main objectives of SentinelAI are to:

1. Build a local security log investigation application.
2. Accept CSV files containing security events.
3. Validate required columns, values, and timestamps.
4. Detect failed-login events followed by a successful login within a defined time window.
5. Display alerts with supporting log evidence.
6. Calculate heuristic risk scores and assign severity labels.
7. Generate AI-assisted investigation summaries using a local LLM.
8. Validate selected AI-generated claims against available evidence.
9. Provide investigation suggestions for analyst review.
10. Test the application using automated unit tests.

## 👥 Target Users

SentinelAI is intended for:

* Cybersecurity students learning security log analysis.
* Beginners exploring Security Operations Center (SOC) workflows.
* Developers learning how to integrate LLMs into applications.
* Security analysts experimenting with sample or authorized log data.

---

## ✨ Key Features

### 1. CSV Security Log Upload

Upload a CSV file containing security events through the Streamlit sidebar.

The application expects the following fields:

* `timestamp`
* `username`
* `source_ip`
* `event_type`
* `status`

### 2. Input Validation

The application validates security log data before performing detection.

Validation includes checks for required columns, missing values, supported event types, supported statuses, and timestamp formats.

Invalid input produces an error message to help the user identify the problem.

### 3. Suspicious Login Detection

SentinelAI detects a selected authentication pattern:

**Multiple failed login events followed by a successful login for the same username within a 15-minute window.**

The application uses rule-based detection rather than relying on an LLM to decide whether the pattern exists.

### 4. Risk Scoring and Severity

Detected alerts can include a heuristic risk score and a severity classification.

Severity labels include:

* High
* Medium
* Low

These scores are indicators for investigation. They are not statistically validated probabilities of compromise.

### 5. Supporting Evidence

Each alert can display relevant source log records.

This helps users review the underlying events instead of relying exclusively on an AI-generated explanation.

### 6. AI Investigation Summary

SentinelAI uses a locally running language model through Ollama to generate a readable investigation summary.

The summary is intended to help explain the observed activity and support further investigation.

### 7. AI Evidence Validation

The application includes basic checks for selected information in AI-generated summaries, including:

* IP addresses.
* Timestamps.
* Username references.
* Failed-login counts.

The checks help identify some inconsistencies between a summary and the available evidence. They do not verify every statement.

### 8. Suggested Investigation Checks

The dashboard provides suggested steps to help users investigate an alert further.

These suggestions are intended for human review and do not automatically execute actions on a real system.

### 9. Investigation Report Export

The application provides an option to download a JSON investigation report containing alert information and related report fields.

### 10. Automated Testing

The project includes unit tests for important detection, validation, AI-summary, and count-checking behaviours.

The latest recorded full test run completed successfully with 52 tests.

---

## 🧰 Technology Stack

| Technology        | Purpose                                       |
| ----------------- | --------------------------------------------- |
| Python            | Application logic and detection rules         |
| Streamlit         | Interactive web dashboard                     |
| Pandas            | Tabular log-data handling                     |
| Ollama            | Local language-model runtime                  |
| Llama 3.2 3B      | Local AI-summary generation model             |
| Requests          | HTTP communication with the Ollama API        |
| Python `unittest` | Automated unit testing                        |
| Git               | Version control                               |
| GitHub            | Repository hosting and portfolio presentation |

The exact dependency versions should be documented in a dependency file if one is maintained in the repository.

---

## 🏗️ System Architecture

SentinelAI follows a workflow that separates log validation, rule-based detection, evidence presentation, and AI-assisted interpretation.

```text
                ┌──────────────────────────┐
                │      User / Analyst      │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Streamlit Dashboard      │
                │ CSV Upload / Sample Data │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Security Log Validation  │
                │ Required Fields / Values │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Rule-Based Detection     │
                │ Failed Login → Success   │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Alert + Supporting       │
                │ Evidence + Risk Score    │
                └────────────┬─────────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
                 ▼                       ▼
    ┌────────────────────────┐  ┌────────────────────────┐
    │ Local Ollama LLM        │  │ Evidence Validation    │
    │ AI Investigation Summary│  │ Selected Claim Checks   │
    └────────────┬───────────┘  └────────────┬───────────┘
                 │                           │
                 └─────────────┬─────────────┘
                               ▼
                ┌──────────────────────────┐
                │ Analyst Reviews Results  │
                │ Suggestions / JSON Export│
                └──────────────────────────┘
```

The diagram represents the intended logical workflow. The exact order in which individual checks run is determined by the implementation.

## 🔄 How SentinelAI Works

### Step 1: Load Security Logs

The user uploads a CSV file or enables the sample CSV option.

### Step 2: Validate Input

The application checks whether the input can be processed and whether the required security log fields contain acceptable values.

### Step 3: Detect Suspicious Activity

The detection logic examines authentication events and looks for failed logins followed by a successful login for the same username within the defined window.

### Step 4: Generate Alerts

Matching patterns produce alerts containing information such as the username, severity, risk score, and relevant event details.

### Step 5: Review Supporting Evidence

The dashboard displays the records associated with the alert so that the user can inspect the source data.

### Step 6: Generate an AI Summary

The application requests an investigation summary from the locally running Ollama model.

### Step 7: Validate Selected Claims

The application performs consistency checks on selected IP-address, timestamp, username, and failed-login-count claims.

### Step 8: Review and Export

The user reviews the alert, summary, validation results, and suggested investigation checks. The application also provides a JSON report export option.

---

## 🔍 Detection Logic

The initial detection pattern is:

**Multiple failed login events followed by a successful login for the same username within 15 minutes.**

The detector examines the available records and associates relevant authentication events with the alert.

### Example

Suppose the logs contain:

| Timestamp | Username | Event | Status  |
| --------- | -------- | ----- | ------- |
| 09:00:00  | alex     | login | failure |
| 09:01:00  | alex     | login | failure |
| 09:02:00  | alex     | login | failure |
| 09:05:00  | alex     | login | success |

These events match the selected detection pattern because failed logins are followed by a successful login for the same username within the detection window.

The application can generate an alert for further investigation.

**Important:** This pattern may have legitimate explanations, such as a user repeatedly entering an incorrect password. It does not prove an attack or successful account compromise.

### Detection Window

The configured detection window is 15 minutes.

The exact event-counting behaviour and time-boundary handling are implemented in the detection logic and covered by automated tests.

### Risk Score

Risk scores are heuristic indicators designed to help prioritize alerts. They should not be interpreted as validated probabilities or definitive measures of malicious activity.

---

## 🤖 AI Investigation Summary

SentinelAI integrates a local LLM through Ollama.

The application uses the configured model to generate an investigation summary for an alert.

The purpose is to make selected security events easier to understand and to provide context for a human investigation.

### Why use a local LLM?

A local model can support experimentation without requiring a paid hosted LLM API.

The actual privacy and resource requirements still depend on the operating environment, model configuration, and how input data is handled.

### Summary caching

The application includes cached-summary behaviour to reuse results for matching alerts and avoid unnecessary repeated model requests.

Automated tests cover important caching and failure-handling behaviours.

### AI is not the source of truth

The security logs and detection logic provide the evidence for the initial finding.

The AI summary is an interpretation that requires review. It should not override the source records.

---

## 🧪 AI Evidence Validation

An important part of SentinelAI is checking selected AI-generated claims against the available security log evidence.

The goal is to identify certain inconsistencies rather than assume that every generated statement is correct.

### 1. IP Address Validation

The application checks IP addresses mentioned in the summary against the IP addresses available in the supporting evidence.

### 2. Timestamp Validation

The application checks selected timestamp claims against the timestamps available in the supporting evidence.

### 3. Username Validation

The validator identifies selected username references and checks them against available evidence. Some username statements may still require manual review.

### 4. Failed Login Count Validation

The count validator compares supported numeric or number-word failed-login claims with the failed login events in the supplied evidence.

It supports examples such as:

```text
The logs show 3 failed login attempts.
```

and:

```text
The logs show three failed login attempts.
```

If the evidence contains two failed login events but the summary claims five, the validator can identify the mismatch.

### Example

**Evidence:**

Two login records have a failure status.

**AI summary:**

```text
The logs show five failed login attempts.
```

**Expected validation outcome:**

```text
Expected failed-login count: 2
Reported count: 5
Result: Mismatch detected
```

### Validation limitations

These checks cover selected claims and formats. They do not establish that the entire AI-generated summary is factually correct.

For example, the current checks do not fully validate every causal explanation, security conclusion, recommendation, or natural-language statement.

A successful validation result means that the implemented checks did not find a mismatch in the claims they examined. It does not prove that the summary is completely accurate or free of hallucinations.

---

## 📂 Project Structure

The following structure reflects the main files identified during development. Confirm the actual repository before publishing, as additional files may exist.

```text
SentinelAI/
│
├── data/
│   └── sample_security_logs.csv
│
├── src/
│   ├── app.py
│   ├── ai_summary.py
│   ├── claim_validation.py
│   ├── detect_suspicious.py
│   ├── read_logs.py
│   ├── validate_ai_summary.py
│   │
│   ├── test_ai_summary.py
│   ├── test_claim_validation.py
│   ├── test_detection.py
│   └── test_validate_ai_summary.py
│
├── README.md
└── .gitignore
```

### Main Files

| File                              | Responsibility                                    |
| --------------------------------- | ------------------------------------------------- |
| `src/app.py`                      | Streamlit dashboard and application workflow      |
| `src/read_logs.py`                | Reading and validating security logs              |
| `src/detect_suspicious.py`        | Rule-based suspicious-login detection             |
| `src/ai_summary.py`               | AI-summary generation and caching                 |
| `src/validate_ai_summary.py`      | Selected AI-summary evidence checks               |
| `src/claim_validation.py`         | Failed-login count validation                     |
| `src/test_ai_summary.py`          | AI-summary and caching tests                      |
| `src/test_claim_validation.py`    | Failed-login count validation tests               |
| `src/test_detection.py`           | Detection, CSV validation, and risk-scoring tests |
| `src/test_validate_ai_summary.py` | AI evidence-validation tests                      |

---

## ⚙️ Installation and Setup

### Prerequisites

Install or prepare the following:

* Python 3.11 or another version compatible with the project's dependencies.
* Git.
* Ollama.
* The local LLM model configured by the application.
* A terminal such as PowerShell or a VS Code terminal.

### 1. Clone the Repository

After publishing the repository to GitHub, run:

```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SentinelAI
```

Replace the placeholder with the actual repository URL.

### 2. Create a Virtual Environment

On Windows:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

If the repository contains a `requirements.txt` file:

```powershell
python -m pip install -r requirements.txt
```

If no dependency file exists, install the project's required packages based on its imports and tested environment. A reproducible dependency file should be maintained before sharing the project.

### 4. Install and Prepare Ollama

Install Ollama using its official installation instructions.

Ensure that the model configured in `src/ai_summary.py` is available locally. The current development configuration uses:

```text
llama3.2:3b
```

If needed, download that model using:

```powershell
ollama pull llama3.2:3b
```

Confirm that the model is available:

```powershell
ollama list
```

Ollama must be running for AI-summary generation to work.

---

## ▶️ Running SentinelAI

From the project root, activate the virtual environment and run:

```powershell
python -m streamlit run src/app.py
```

Streamlit will display the local application address in the terminal.

Open that address in a browser.

### Basic Usage

1. Open the SentinelAI dashboard.
2. Upload a security log CSV or enable the sample CSV option.
3. Review the loaded log records.
4. Inspect the generated security alerts.
5. Open an alert to view its supporting evidence.
6. Review the AI Investigation Summary.
7. Review the evidence-validation and failed-login-count results.
8. Read the suggested investigation checks.
9. Download the JSON investigation report if required.

AI-summary generation depends on the local Ollama service and configured model.

---

## 🧪 Running Automated Tests

SentinelAI uses Python's built-in `unittest` framework.

Run all discovered test files from the project root:

```powershell
python -m unittest discover -s src -p "test_*.py" -v
```

To run only the failed-login count validation tests:

```powershell
python -m unittest discover -s src -p "test_claim_validation.py" -v
```

To run the detection tests:

```powershell
python -m unittest discover -s src -p "test_detection.py" -v
```

### Latest Recorded Test Results

During development, the full test suite completed successfully:

```text
Ran 52 tests in 0.095s

OK
```

This result records the test run performed during development. It is not a guarantee that every possible input or runtime environment has been tested.

### Areas Covered by Tests

The existing tests cover important behaviours involving:

* CSV input validation.
* Suspicious login detection.
* Detection time windows.
* Risk-score and severity thresholds.
* AI-summary generation and error handling.
* AI-summary caching.
* Selected IP-address and timestamp checks.
* Failed-login count validation.
* Numeric and supported number-word count claims.
* Detection of incorrect failed-login counts.

---

## 📄 Sample Input Format

SentinelAI expects a CSV containing these fields:

```csv
timestamp,username,source_ip,event_type,status
2026-10-23T09:00:00,alex,192.0.2.10,login,failure
2026-10-23T09:01:00,alex,192.0.2.10,login,failure
2026-10-23T09:02:00,alex,192.0.2.10,login,failure
2026-10-23T09:05:00,alex,192.0.2.10,login,success
```

The example uses documentation-only IP addresses and synthetic authentication events.

Use synthetic or authorized data when testing the application. Do not upload confidential logs to an environment unless you are authorized to process them.

---

## 🔬 Example Investigation Workflow

Consider a dataset with several failed login attempts followed by a successful login for the same username.

SentinelAI can:

1. Validate the input records.
2. Identify the matching authentication pattern.
3. Generate an alert using the rule-based detector.
4. Display the associated log evidence.
5. Generate an AI-assisted investigation summary.
6. Compare selected claims in the summary with the evidence.
7. Present investigation suggestions for human review.

The resulting alert is a finding for investigation, not a confirmed incident.

---

## 🔐 Security and Safety

SentinelAI is designed for defensive security learning and investigation.

### Intended Use

* Use synthetic or authorized security logs.
* Review alerts before drawing conclusions.
* Verify AI-generated statements against source evidence.
* Keep confidential data out of public sample files and repositories.

### Non-Goals

The current V1 prototype is not designed to provide:

* Autonomous incident response.
* Real-time security monitoring.
* Enterprise SIEM integration.
* Automatic remediation of real systems.
* A mobile application.
* A guarantee that AI-generated statements are correct.

The application should not be treated as a production-grade security monitoring or response platform without additional engineering, testing, and security review.

---

## ⚠️ Current Limitations

The current prototype has several limitations:

1. Detection focuses on a selected authentication pattern rather than all security threats.
2. The AI summary may contain unsupported or inaccurate statements.
3. Evidence validation covers selected claims and does not validate every sentence.
4. Username validation may require manual review.
5. Heuristic risk scores are not validated probabilities.
6. AI-summary generation depends on the local model and available system resources.
7. The current test suite covers implemented behaviours but does not prove the absence of all defects.
8. The application has not been established as production-ready through a formal security assessment.

These limitations should be considered when interpreting the results.

---

## 🛣️ Future Improvements

Potential future development includes:

### AI Evaluation

* More comprehensive unsupported-claim detection.
* Evaluation of security conclusions and recommendations.
* Risk-score consistency checks.
* A structured AI-evaluation dataset.
* False-positive and false-negative analysis.
* More systematic hallucination testing.

### Detection Improvements

* Additional authentication-event patterns.
* Correlation of related alerts into incidents.
* More configurable detection windows.
* Improved evidence selection and reporting.

### Application Improvements

* Better validation feedback.
* More detailed investigation reports.
* Additional automated tests.
* Reproducible dependency management.
* Improved documentation and dashboard usability.

### Deployment and Portfolio

* Prepare a public GitHub repository.
* Add verified screenshots and demonstration instructions.
* Evaluate suitable free deployment options.
* Document deployment limitations and security considerations.

These are potential improvements, not claims about completed features.

---

## 🎓 Learning Outcomes

The development of SentinelAI provides practical experience with:

* Python application development.
* CSV processing and input validation.
* Rule-based cybersecurity detection.
* Time-window-based event analysis.
* Risk scoring and severity classification.
* Local LLM integration using Ollama.
* AI-summary generation and caching.
* Evidence consistency checks.
* Streamlit dashboard development.
* Unit testing with `unittest`.
* Defensive cybersecurity project design.
* Technical documentation and GitHub portfolio preparation.

---

## ✅ Project Goals and Success Criteria

The original V1 goals are to:

* [x] Read valid sample security logs.
* [x] Validate CSV input.
* [x] Detect the selected suspicious-login pattern.
* [x] Display alerts with supporting evidence.
* [x] Generate AI-assisted investigation summaries.
* [x] Provide investigation suggestions.
* [x] Run the application locally.
* [x] Maintain automated tests for key behaviours.
* [x] Implement basic consistency checks for selected AI-generated claims.

The checks above reflect implemented capabilities and recorded test results during development. They do not imply that every possible claim is validated or that the application is production-ready.

---

## 👨‍💻 Author

**SentinelAI — Security Alert Investigation Copilot**

Developed as a practical project exploring the intersection of AI Engineering and defensive cybersecurity.

**Core focus:** Rule-based security detection, local LLM integration, evidence-grounded investigation, and automated testing.

---

*SentinelAI is an educational and defensive security project. Alerts and AI-generated summaries require human review and should not be treated as definitive proof of malicious activity or account compromise.