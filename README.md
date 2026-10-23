# SentinelAI

## Security Alert Investigation Copilot

### 1. Problem Statement

Security analysts need to review security logs and identify events that may require investigation. SentinelAI will help analysts interpret uploaded logs, identify suspicious patterns, and prepare evidence-based investigation reports.

### 2. Target User

A security analyst or IT student working with sample security logs.

### 3. V1 Goal

Build a local web application that accepts a CSV security log, validates the data, detects selected suspicious patterns, and presents findings with supporting evidence.

### 4. Functional Requirements

* Accept a CSV file containing security events.
* Validate required fields and data types.
* Detect selected patterns using transparent rules.
* Display relevant log records as evidence.
* Generate a readable investigation summary.
* Clearly distinguish observed facts from AI-generated interpretations.
* Provide investigation suggestions for analyst review.

### 5. Safety and Scope

* Use synthetic or authorized logs only.
* Do not execute actions on real systems.
* Do not treat an AI-generated suspicion as a confirmed incident.
* Do not include personal or confidential data in sample files.

### 6. Initial Data Fields

* timestamp
* username
* source_ip
* event_type
* status

### 7. Initial Pattern

Multiple failed login events followed by a successful login for the same username.

### 8. V1 Non-Goals

* Autonomous incident response.
* Real-time monitoring.
* Enterprise SIEM integration.
* Mobile application.
* Paid cloud services.

### 9. Success Criteria

* The application can read a valid sample CSV.
* Invalid files produce understandable error messages.
* Detected patterns link to the relevant source records.
* The report separates evidence from interpretation.
* The application can be demonstrated locally.
