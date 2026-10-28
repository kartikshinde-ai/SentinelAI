"""
SentinelAI - Local AI investigation summaries using Ollama.
"""

import hashlib
import json

import requests
import streamlit as st


OLLAMA_API_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "llama3.2:3b"
REQUEST_TIMEOUT = 180

# Store successful summaries in the current Streamlit session.
SUMMARY_CACHE_KEY = "_sentinelai_summary_cache"


def generate_investigation_summary(alert: dict) -> dict:
    """
    Generate an evidence-grounded investigation summary.

    Rule-based detection remains the source of the alert.
    """

    username = str(alert.get("username", "Unknown"))
    severity = str(alert.get("severity", "Unrated"))
    finding = str(alert.get("finding", "No finding provided"))
    risk_score = alert.get("risk_score", "Not available")
    evidence = alert.get("evidence", [])
    investigation_steps = alert.get("investigation_steps", [])

    prompt_data = {
        "username": username,
        "severity": severity,
        "risk_score": risk_score,
        "finding": finding,
        "supporting_evidence": evidence,
        "existing_investigation_steps": investigation_steps,
    }

    system_prompt = """
You are SentinelAI, a defensive cybersecurity investigation assistant.

Rules:
1. Use only the supplied alert and evidence.
2. Never invent events, IP addresses, timestamps, or facts.
3. Explain that a suspicious pattern is not proof of compromise.
4. Distinguish observed evidence from possible interpretations.
5. If evidence is insufficient, explicitly say so.
6. Do not recommend offensive actions or accessing real systems.
7. Keep the response concise and suitable for a security analyst.
8. Return plain text with these headings:
   Summary
   Evidence observed
   Possible interpretation
   Recommended investigation checks
   Limitations
"""

    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": DEFAULT_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": system_prompt,
                    },
                    {
                        "role": "user",
                        "content": (
                            "Prepare an investigation summary from this alert:\n"
                            f"{json.dumps(prompt_data, default=str)}"
                        ),
                    },
                ],
                "stream": False,
                "options": {
                    "temperature": 0.1,
                },
            },
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()
        result = response.json()

        summary = result.get("message", {}).get("content", "").strip()

        if not summary:
            return {
                "success": False,
                "summary": "",
                "error": "Ollama returned an empty response.",
            }

        return {
            "success": True,
            "summary": summary,
            "error": None,
        }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "summary": "",
            "error": (
                "Ollama took too long to respond. "
                "Try again or check whether the model is running."
            ),
        }

    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "summary": "",
            "error": (
                "Could not connect to Ollama. "
                "Check that the Ollama service is running."
            ),
        }

    except requests.exceptions.RequestException as error:
        return {
            "success": False,
            "summary": "",
            "error": f"Ollama request failed: {error}",
        }

    except (ValueError, TypeError, AttributeError) as error:
        return {
            "success": False,
            "summary": "",
            "error": f"Could not process the Ollama response: {error}",
        }


def generate_cached_investigation_summary(alert: dict) -> dict:
    """
    Reuse a successful summary for identical alert content
    within the current Streamlit session.

    Failed summaries are not cached.
    """

    # Convert the complete alert into stable JSON.
    alert_json = json.dumps(
        alert,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )

    # Different alert content produces a different cache key.
    cache_key = hashlib.sha256(
        f"{DEFAULT_MODEL}:{alert_json}".encode("utf-8")
    ).hexdigest()

    cache = st.session_state.get(SUMMARY_CACHE_KEY)

    if not isinstance(cache, dict):
        cache = {}
        st.session_state[SUMMARY_CACHE_KEY] = cache

    if cache_key in cache:
        return cache[cache_key]

    result = generate_investigation_summary(alert)

    # Cache only successful, non-empty summaries.
    if result.get("success") and result.get("summary", "").strip():
        cache[cache_key] = result

    return result

