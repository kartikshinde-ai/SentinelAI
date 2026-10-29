from pathlib import Path
import sys
import io
import json

import pandas as pd
import streamlit as st


# ----------------------------
# Project paths and imports
# ----------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from read_logs import (
    read_security_logs,
    read_security_logs_from_stream,
)
from detect_suspicious import detect_failed_then_success
from ai_summary import generate_cached_investigation_summary
from validate_ai_summary import validate_ai_summary
from claim_validation import validate_failed_login_count

# ----------------------------
# Page configuration
# ----------------------------
st.set_page_config(
    page_title="SentinelAI | Security Copilot",
    page_icon="🛡️",
    layout="wide",
)


# ----------------------------
# Custom styling
# ----------------------------
st.markdown(
    """
    <style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    .main-title {
        font-size: 2.5rem;
        font-weight: 750;
        margin-bottom: 0;
    }
    .subtitle {
        color: #8b949e;
        font-size: 1rem;
        margin-top: 0.25rem;
    }
    .notice {
        padding: 0.8rem 1rem;
        border-radius: 0.5rem;
        background: rgba(128, 128, 128, 0.12);
        border: 1px solid rgba(128, 128, 128, 0.3);
        margin: 1rem 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ----------------------------
# Header
# ----------------------------
st.markdown(
    '<div class="main-title">🛡️ SentinelAI</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">Security Alert Investigation Copilot</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="notice">
    Defensive security analytics for synthetic or authorized security logs.
    Alerts identify patterns for investigation; they do not prove compromise.
    </div>
    """,
    unsafe_allow_html=True,
)


# ----------------------------
# Sidebar
# ----------------------------
st.sidebar.header("Investigation Settings")

uploaded_file = st.sidebar.file_uploader(
    "Upload security logs (CSV)",
    type=["csv"],
    help=(
        "Required columns: timestamp, username, source_ip, "
        "event_type, status."
    ),
)

use_sample = st.sidebar.checkbox(
    "Use project sample CSV",
    value=True,
)

sample_file = PROJECT_ROOT / "data" / "sample_security_logs.csv"

st.sidebar.caption("Detection window: 15 minutes")
st.sidebar.caption("Detection type: Failed login followed by success")


# ----------------------------
# Load logs
# ----------------------------
logs = []
load_error = None
data_source = None

if uploaded_file is not None:
    try:
        uploaded_file.seek(0)

        text_stream = io.TextIOWrapper(
            io.BytesIO(uploaded_file.getvalue()),
            encoding="utf-8-sig",
        )

        logs = read_security_logs_from_stream(text_stream)
        data_source = uploaded_file.name

    except Exception as error:
        load_error = str(error)

elif use_sample:
    try:
        logs = read_security_logs(sample_file)
        data_source = "data/sample_security_logs.csv"

    except Exception as error:
        load_error = str(error)


# ----------------------------
# Show validation errors
# ----------------------------
if load_error:
    st.error(f"Could not load the CSV file: {load_error}")
    st.info(
        "Check the CSV headers, required values, timestamp format, "
        "event types and status values."
    )
    st.stop()

if not logs:
    st.info(
        "Upload a CSV file or enable 'Use project sample CSV' "
        "in the sidebar to begin an investigation."
    )
    st.stop()


# ----------------------------
# Run detection
# ----------------------------
try:
    alerts = detect_failed_then_success(logs)

except Exception as error:
    st.error(f"Detection failed: {error}")
    st.stop()


# ----------------------------
# Summary metrics
# ----------------------------
high_count = sum(
    1 for alert in alerts
    if alert.get("severity") == "High"
)

medium_count = sum(
    1 for alert in alerts
    if alert.get("severity") == "Medium"
)

low_count = sum(
    1 for alert in alerts
    if alert.get("severity") == "Low"
)

st.caption(f"Data source: {data_source}")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total log records", len(logs))
col2.metric("Total alerts", len(alerts))
col3.metric("High severity", high_count)
col4.metric("Medium severity", medium_count)

st.divider()


# ----------------------------
# Log overview
# ----------------------------
with st.expander("View validated security logs"):
    logs_df = pd.DataFrame(logs)

    st.dataframe(
        logs_df,
        use_container_width=True,
        hide_index=True,
    )


# ----------------------------
# Alert investigation
# ----------------------------
st.subheader("Security Alert Investigations")

if not alerts:
    st.success(
        "No matching failed-login-then-success patterns were detected "
        "in the loaded records."
    )

else:
    severity_filter = st.multiselect(
        "Filter by severity",
        options=["High", "Medium", "Low"],
        default=["High", "Medium", "Low"],
    )

    filtered_alerts = [
        alert
        for alert in alerts
        if alert.get("severity", "Low") in severity_filter
    ]

    if not filtered_alerts:
        st.info("No alerts match the selected severity filters.")

    for index, alert in enumerate(filtered_alerts, start=1):
        username = alert.get("username", "Unknown user")
        severity = alert.get("severity", "Unrated")
        risk_score = alert.get("risk_score")

        title = f"Alert {index}: {username} — {severity}"

        with st.expander(title, expanded=(index == 1)):

            # ----------------------------
            # Alert metrics
            # ----------------------------
            top1, top2, top3 = st.columns(3)

            top1.metric("Username", username)
            top2.metric("Severity", severity)

            if risk_score is not None:
                top3.metric("Risk score", f"{risk_score}/100")
            else:
                top3.metric("Risk score", "Not available")

            # ----------------------------
            # Finding
            # ----------------------------
            st.markdown("#### Finding")

            st.write(
                alert.get(
                    "finding",
                    (
                        f"{alert.get('failed_attempts', 0)} failed login "
                        "attempt(s) were followed by a successful login."
                    ),
                )
            )

            # ----------------------------
            # Alert details
            # ----------------------------
            details1, details2 = st.columns(2)

            with details1:
                st.write(
                    "**Failed attempts:**",
                    alert.get("failed_attempts", 0),
                )

                st.write(
                    "**First failure:**",
                    alert.get("first_failure", "Not available"),
                )

                st.write(
                    "**Last failure:**",
                    alert.get("last_failure", "Not available"),
                )

            with details2:
                st.write(
                    "**Successful login:**",
                    alert.get("successful_login", "Not available"),
                )

                st.write(
                    "**Successful login source IP:**",
                    alert.get("source_ip", "Not available"),
                )

                st.write("**Detection window:** 15 minutes")

            # ----------------------------
            # Supporting evidence
            # ----------------------------
            st.markdown("#### Supporting evidence")

            evidence = alert.get("evidence", [])

            if evidence:
                evidence_df = pd.DataFrame(evidence)

                st.dataframe(
                    evidence_df,
                    use_container_width=True,
                    hide_index=True,
                )

            else:
                st.warning(
                    "No supporting evidence was attached to this alert."
                )

            # ----------------------------
            # AI Investigation Summary
            # ----------------------------
            st.markdown("#### AI Investigation Summary")

            with st.spinner("AI is analyzing the alert..."):
                ai_result = generate_cached_investigation_summary(alert)

            if ai_result.get("success"):
                ai_summary = ai_result.get("summary", "")

                st.markdown(ai_summary)

                # ----------------------------
                # AI Evidence Validation
                # ----------------------------
                st.markdown("#### AI Evidence Validation")

                validation_result = validate_ai_summary(
                    ai_summary,
                    evidence,
                )

                # ----------------------------
                # Failed Login Count Validation
                # ----------------------------
                st.markdown("#### Failed Login Count Validation")

                count_validation = validate_failed_login_count(
                    ai_summary,
                    evidence,
                )

                if not count_validation.get("checked"):
                    st.info(
                        "No supported numeric failed-login count "
                        "claim was found. Count validation was not performed."
                    )

                elif count_validation.get("valid"):
                    st.success(
                        "Failed login count validation passed. "
                        f"Evidence contains "
                        f"{count_validation['expected_count']} failed "
                        "login attempt(s), matching the AI summary."
                    )

                else:
                    st.warning(
                        "Failed login count mismatch detected! "
                        f"Evidence shows "
                        f"{count_validation['expected_count']} failed "
                        "login attempt(s), but the AI summary reports "
                        f"{count_validation['reported_counts']}."
                    )

                with st.expander("View failed login count details"):
                    st.write(
                        "**Failed logins found in evidence:**",
                        count_validation.get("expected_count"),
                    )

                    st.write(
                        "**Counts reported by AI:**",
                        count_validation.get("reported_counts", []),
                    )

                    st.write(
                        "**Detected mismatches:**",
                        count_validation.get("mismatches", []),
                    )

                if validation_result.get("valid"):
                    st.success(
                        "Evidence validation passed: no unsupported "
                        "IP addresses or timestamps were detected."
                    )

                else:
                    st.warning(
                        "Evidence validation requires review: "
                        + str(
                            validation_result.get(
                                "error",
                                "The summary could not be fully validated.",
                            )
                        )
                    )

                unsupported = validation_result.get(
                    "unsupported", {}
                )

                unsupported_ips = unsupported.get(
                    "ip_addresses", []
                )

                unsupported_timestamps = unsupported.get(
                    "timestamps", []
                )

                if unsupported_ips:
                    st.error(
                        "Unsupported IP addresses: "
                        + ", ".join(unsupported_ips)
                    )

                if unsupported_timestamps:
                    st.error(
                        "Unsupported timestamps: "
                        + ", ".join(unsupported_timestamps)
                    )

                checked = validation_result.get("checked", {})

                with st.expander("View validation details"):
                    st.write(
                        "**IP addresses checked:**",
                        checked.get("ip_addresses", []),
                    )

                    st.write(
                        "**Timestamps checked:**",
                        checked.get("timestamps", []),
                    )

                    st.write(
                        "**Usernames identified from evidence:**",
                        checked.get("usernames", []),
                    )

                    st.caption(
                        "This basic consistency check does not prove "
                        "that the AI summary is completely correct. "
                        "Username claims are not fully validated."
                    )

            else:
                st.warning(
                    "AI summary could not be generated: "
                    + ai_result.get("error", "Unknown error")
                )

            # ----------------------------
            # Suggested investigation checks
            # ----------------------------
            st.markdown("#### Suggested investigation checks")

            investigation_steps = alert.get(
                "investigation_steps",
                [
                    "Verify whether the successful login was expected.",
                    "Review the source IP address and login time.",
                    "Check for similar activity affecting other accounts.",
                    "Confirm the finding using additional authorized log sources.",
                ],
            )

            for step in investigation_steps:
                st.markdown(f"- {step}")

            # ----------------------------
            # Assessment note
            # ----------------------------
            st.info(
                alert.get(
                    "assessment_note",
                    (
                        "This alert identifies a pattern for review. "
                        "It does not confirm that an account was compromised."
                    ),
                )
            )


# ----------------------------
# Export investigation report
# ----------------------------
st.divider()
st.subheader("Export Investigation Report")

if alerts:
    report = {
        "report_title": "SentinelAI Security Alert Report",
        "data_source": data_source,
        "total_log_records": len(logs),
        "total_alerts": len(alerts),
        "alerts": alerts,
        "assessment_note": (
            "Alerts are rule-based findings for analyst review. "
            "They do not independently confirm account compromise."
        ),
    }

    report_json = json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
        default=str,
    )

    st.download_button(
        label="Download JSON investigation report",
        data=report_json,
        file_name="sentinelai_investigation_report.json",
        mime="application/json",
    )


# ----------------------------
# Footer
# ----------------------------
st.caption(
    "SentinelAI V1 • Rule-based detection • "
    "Risk scores are heuristic indicators, not validated probabilities."
)

