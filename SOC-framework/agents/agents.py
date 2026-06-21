"""
agents/agents.py — L1 agents using the SecurityFramework.

"""

import json
import os
import re
import logging
from openai import OpenAI
from framework.security import SecurityFramework
from memory.store import MemoryStore

logger = logging.getLogger(__name__)

_openai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

from framework.security import TRIAGE_TOOLS, ENRICHMENT_TOOLS, RESPONSE_TOOLS  # single source of truth

# ── Human-agent trust manipulation patterns ─────────────────────────────
# Applied to the response agent's justification field to detect if the agent
# is being manipulated into requesting unnecessary human approvals or into
# making the analyst act on fabricated urgency.
_TRUST_MANIPULATION_PATTERNS = [
    r"(critical|urgent|immediate)\s+(action|response|approval)\s+required\s+by\s+(policy|regulation|compliance)",
    r"failure\s+to\s+approve\s+will\s+(result|cause|lead)",
    r"(security\s+team|management|ciso|ceo)\s+(has\s+)?(requested|mandated|ordered|requires?)",
    r"(regulatory|legal|compliance)\s+(requirement|obligation|mandate)\s+(requires?|demands?|forces?)",
    r"you\s+(must|have\s+to|need\s+to)\s+approve\s+(this|immediately|now|urgently)",
    r"automatic(ally)?\s+(approved|authorized|executed)\s+(if|unless|when)\s+not\s+(reviewed|rejected)",
    r"(override|bypass)\s+(security|approval|review)\s+(process|procedure|requirement)",
]
_COMPILED_TRUST = [re.compile(p, re.IGNORECASE)
                   for p in _TRUST_MANIPULATION_PATTERNS]


def _validate_response_justification(response: dict) -> dict:
    """
    [NEW] Human-agent trust manipulation validation.
    Scans the response agent's summary and action reasons for patterns
    that attempt to manipulate the analyst into approving actions under
    false urgency or fabricated authority.
    Returns the response with a warning flag if manipulation is detected.
    """
    fields_to_check = [response.get("summary", "")]
    for action in response.get("recommended_actions", []):
        fields_to_check.append(action.get("reason", ""))

    for text in fields_to_check:
        if not text:
            continue
        for pattern in _COMPILED_TRUST:
            if pattern.search(text):
                logger.warning(
                    f"[TRUST MANIPULATION] Suspicious justification detected "
                    f"in response agent output. Pattern: /{pattern.pattern}/"
                )
                response["_trust_manipulation_warning"] = (
                    "Response contains justification patterns associated with "
                    "human-agent trust manipulation. Human review recommended."
                )
                response["requires_human_approval"] = True
                return response

    return response


def _to_openai(tools: list) -> list:
    return [
        {
            "type": "function",
            "function": {
                "name":        t["name"],
                "description": t["description"],
                "parameters":  t.get("parameters",
                               {"type": "object", "properties": {}}),
            }
        }
        for t in tools
    ]


def _run_agent(
    role:          str,
    system_prompt: str,
    user_message:  str,
    framework:     SecurityFramework,
    allowed_tools: set,
    max_iters:     int = 8,
) -> str:
    all_tools    = framework.get_tools_for(role)
    tools        = [t for t in all_tools if t["name"] in allowed_tools]
    openai_tools = _to_openai(tools)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_message},
    ]

    for _ in range(max_iters):
        resp = _openai.chat.completions.create(
            model       = MODEL,
            messages    = messages,
            tools       = openai_tools or None,
            tool_choice = "auto" if openai_tools else None,
            temperature = 0.1,
        )
        msg = resp.choices[0].message
        if not msg.tool_calls:
            return msg.content or ""

        messages.append(msg)

        for tc in msg.tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                args = {}

            logger.info(f"    -> {name}({args})")

            try:
                result = framework.call_tool(role, name, args)
            except (PermissionError, ValueError, RuntimeError) as e:
                result = f"BLOCKED BY SECURITY FRAMEWORK: {e}"
                logger.warning(f"    BLOCKED: {e}")
            except Exception as e:
                result = f"ERROR: {e}"
                logger.error(f"    ERROR: {e}")

            messages.append({
                "role":         "tool",
                "tool_call_id": tc.id,
                "content":      result,
            })

    return "ERROR: max iterations reached."


# ══════════════════════════════════════════════════════════════════════════════
# AGENT 1 — TRIAGE
# ══════════════════════════════════════════════════════════════════════════════

def run_triage_agent(alert_text: str, framework: SecurityFramework,
                     memory: MemoryStore,
                     session_id: str = None) -> dict:
    logger.info("[TRIAGE] Starting")

    raw_context = memory.get_context()
    context     = framework.validate_memory_context(raw_context)
    recent      = memory.get_recent_alerts(limit=3)

    system = f"""\
You are a SOC Level 1 triage analyst connected to Wazuh SIEM.

Persistent context from memory:
{json.dumps(context, indent=2) if context else "No context stored."}

Recent alert history (last 3):
{json.dumps(recent, indent=2) if recent else "No previous alerts."}

Analyze the alert and classify it.
Respond ONLY with a valid JSON object, no markdown:
{{
  "severity":          "critical"|"high"|"medium"|"low"|"informational",
  "threat_type":       "string",
  "is_false_positive": true|false,
  "confidence":        0.0-0.99,
  "justification":     "one sentence",
  "escalate":          true|false
}}"""

    raw = _run_agent("triage_agent", system,
                     f"Analyze:\n{alert_text}",
                     framework, TRIAGE_TOOLS)
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = {"error": "non-JSON", "raw": raw}

    if "error" not in result:
        aid   = (re.search(r"Alert ID:\s*(\S+)", alert_text) or
                 type("x", (), {"group": lambda s, n: "unknown"})()).group(1)
        aname = (re.search(r"Agent:\s*(\S+)", alert_text) or
                 type("x", (), {"group": lambda s, n: "unknown"})()).group(1)
        memory.save_alert(aid, aname, result, {})

    return result


# ══════════════════════════════════════════════════════════════════════════════
# AGENT 2 — ENRICHMENT
# ══════════════════════════════════════════════════════════════════════════════

def run_enrichment_agent(alert_text: str, triage: dict,
                          framework: SecurityFramework,
                          memory: MemoryStore,
                          session_id: str = None) -> dict:
    logger.info("[ENRICHMENT] Starting")

    raw_context = memory.get_context()
    context     = framework.validate_memory_context(raw_context)
    am          = re.search(r"Agent:\s*(\S+)", alert_text)
    aname       = am.group(1) if am else None
    prior       = memory.get_agent_knowledge(aname) if aname else None

    system = f"""\
You are a SOC Level 1 enrichment analyst connected to Wazuh SIEM.

Persistent context from memory:
{json.dumps(context, indent=2) if context else "No context stored."}

Prior knowledge about this host:
{json.dumps(prior, indent=2) if prior else "No prior knowledge stored."}

Triage result:
{json.dumps(triage, indent=2)}

Use available tools to gather context about the affected agent.
Respond ONLY with a valid JSON object, no markdown:
{{
  "agent_info":      {{"id":"...","name":"...","ip":"...","os":"..."}},
  "open_ports":      ["list"],
  "vulnerabilities": ["list of CVEs"],
  "risk_indicators": ["list of findings"],
  "context_summary": "2-3 sentence summary"
}}"""

    raw = _run_agent("enrichment_agent", system,
                     f"Enrich:\n{alert_text}",
                     framework, ENRICHMENT_TOOLS)
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = {"error": "non-JSON", "raw": raw}

    if "error" not in result and aname:
        info = result.get("agent_info", {})
        memory.upsert_agent_knowledge(
            agent_name = aname,
            ip         = info.get("ip", "unknown"),
            cves       = result.get("vulnerabilities", []),
            risk_level = triage.get("severity", "unknown"),
            notes      = result.get("context_summary", ""),
        )
        aid = (re.search(r"Alert ID:\s*(\S+)", alert_text) or
               type("x", (), {"group": lambda s, n: "unknown"})()).group(1)
        memory.save_alert(aid, aname, triage, result)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# AGENT 3 — RESPONSE
# ══════════════════════════════════════════════════════════════════════════════

def run_response_agent(alert_text: str, triage: dict, enrichment: dict,
                        framework: SecurityFramework,
                        memory: MemoryStore,
                        session_id: str = None) -> dict:
    logger.info("[RESPONSE] Starting")

    raw_context = memory.get_context()
    context     = framework.validate_memory_context(raw_context)
    recent      = memory.get_recent_alerts(limit=5)

    system = f"""\
You are a SOC Level 1 response analyst connected to Wazuh SIEM.

Persistent context from memory:
{json.dumps(context, indent=2) if context else "No context stored."}

Recent alert history (last 5):
{json.dumps(recent, indent=2) if recent else "No history."}

DO NOT execute actions, only recommend them.
Every destructive action must set requires_human_approval: true.

Respond ONLY with a valid JSON object, no markdown:
{{
  "recommended_actions": [
    {{
      "action":     "block_ip|isolate_host|monitor|escalate|close",
      "target":     "IP or agent name",
      "priority":   "immediate|within_1h|within_24h",
      "reason":     "why",
      "reversible": true|false
    }}
  ],
  "requires_human_approval": true|false,
  "escalate_to_l2":          true|false,
  "summary":                 "one paragraph"
}}"""

    user_msg = (
        f"Alert:\n{alert_text}\n\n"
        f"Triage:\n{json.dumps(triage, indent=2)}\n\n"
        f"Enrichment:\n{json.dumps(enrichment, indent=2)}"
    )
    raw = _run_agent("response_agent", system, user_msg,
                     framework, RESPONSE_TOOLS)
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "non-JSON", "raw": raw}

    # [NEW] Human-agent trust manipulation validation
    result = _validate_response_justification(result)

    return result