"""
main.py — SOC Multi-Agent System with Security Framework.

Group 2 controls added:
  - session_id: UUID per pipeline execution for session state integrity
  - oversight saturation: pipeline rate limit at orchestrator level
  - human-agent trust manipulation: justification validation in response agent
"""

import os
import sys
import json
import uuid
import time
import logging
import argparse
from collections import deque
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(
    level   = os.getenv("LOG_LEVEL", "INFO"),
    format  = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt = "%H:%M:%S",
)
logger = logging.getLogger(__name__)

WAZUH_URL  = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8085/mcp")
EVIL_URL   = os.getenv("EVIL_MCP_URL",   "http://127.0.0.1:8089/mcp")
MEMORY_DIR = os.getenv("MEMORY_DIR",     "./memory_data")

# ── [NEW] Oversight saturation control ────────────────────────────────────────
# Limits the number of complete pipelines that can request human approval
# within a sliding time window. Prevents consent fatigue attacks where the
# system floods the analyst with approval requests.
_APPROVAL_WINDOW_SECONDS = 3600   # 1 hour
_MAX_APPROVALS_PER_WINDOW = 10    # max human approval requests per hour
_pipeline_approval_timestamps: deque = deque()


def _check_oversight_saturation(requires_approval: bool) -> bool:
    """
    [NEW] Oversight saturation / consent fatigue control.
    Returns True if the approval request is allowed, False if rate-limited.
    """
    if not requires_approval:
        return True

    now = time.time()
    # Remove timestamps outside the window
    while _pipeline_approval_timestamps and \
          now - _pipeline_approval_timestamps[0] > _APPROVAL_WINDOW_SECONDS:
        _pipeline_approval_timestamps.popleft()

    if len(_pipeline_approval_timestamps) >= _MAX_APPROVALS_PER_WINDOW:
        logger.warning(
            f"[OVERSIGHT SATURATION] BLOCKED: "
            f"{_MAX_APPROVALS_PER_WINDOW} human approval requests already "
            f"issued in the last {_APPROVAL_WINDOW_SECONDS//60} minutes. "
            f"Possible consent fatigue attack."
        )
        return False

    _pipeline_approval_timestamps.append(now)
    return True


def _section(title, data):
    print(f"\n-- {title} {'-'*(55-len(title))}")
    if "error" in data:
        print(f"  WARNING: {data['error']}")
        return
    for k, v in data.items():
        if isinstance(v, list):
            print(f"  {k}:")
            for item in v[:5]:
                print(f"    * {item}")
        elif isinstance(v, dict):
            print(f"  {k}: {json.dumps(v)}")
        else:
            print(f"  {k}: {str(v)[:120]}")


def show_memory(memory):
    stats = memory.stats()
    print(f"\n{'='*55}")
    print(f"  MEMORY STATE")
    print(f"{'='*55}")
    print(f"  Alerts stored   : {stats['alerts_stored']}")
    print(f"  Agents known    : {stats['agents_known']}")
    print(f"  Context entries : {stats['context_entries']}")
    ctx = memory.get_context()
    if ctx:
        print(f"\n  Context store (attack surface):")
        for k, v in ctx.items():
            print(f"    [{k}] {str(v)[:100]}")
    recent = memory.get_recent_alerts(limit=3)
    if recent:
        print(f"\n  Recent alerts:")
        for a in recent:
            print(f"    {a['timestamp'][11:19]} | {a['agent_name']} | "
                  f"{a['severity']} | fp={a['is_fp']}")
    print(f"{'='*55}\n")


def run(custom_alert=None):
    from mcp.client import MCPClient
    from memory.store import MemoryStore
    from framework.security import SecurityFramework
    from agents.agents import (run_triage_agent,
                                run_enrichment_agent,
                                run_response_agent)

    # [NEW] Session ID — unique per pipeline execution.
    # Provides session-level traceability in the audit log and enables
    # detection of session state corruption across pipeline runs.
    session_id = str(uuid.uuid4())
    logger.info(f"Session ID: {session_id}")

    memory = MemoryStore(MEMORY_DIR, session_id=session_id)

    print(f"\n{'='*60}")
    print(f"  SOC MULTI-AGENT SYSTEM + SECURITY FRAMEWORK")
    print(f"  Wazuh MCP  : {WAZUH_URL}")
    print(f"  Evil MCP   : {EVIL_URL}")
    print(f"  Memory dir : {MEMORY_DIR}")
    print(f"  Session ID : {session_id[:16]}...")
    print(f"{'='*60}")

    stats = memory.stats()
    print(f"\n  Memory: {stats['alerts_stored']} alerts, "
          f"{stats['agents_known']} agents known, "
          f"{stats['context_entries']} context entries")

    # Connect servers
    wazuh_mcp = MCPClient(WAZUH_URL)
    evil_mcp  = MCPClient(EVIL_URL)

    wazuh_mcp.connect()
    framework = SecurityFramework(wazuh_mcp, session_id=session_id)
    print(f"\n  Wazuh MCP connected")

    # Tool registration validation for Wazuh
    print(f"\n  Running tool registration validator...")
    wazuh_tools_raw   = wazuh_mcp.list_tools()
    wazuh_tools_clean = framework.register_server(WAZUH_URL, wazuh_tools_raw)
    print(f"  Wazuh: {len(wazuh_tools_clean)}/{len(wazuh_tools_raw)} tools passed")

    evil_available = False
    try:
        evil_mcp.connect()
        evil_tools_raw   = evil_mcp.list_tools()
        evil_tools_clean = framework.register_server(EVIL_URL, evil_tools_raw)
        blocked_count    = len(evil_tools_raw) - len(evil_tools_clean)
        print(f"  Evil:  {len(evil_tools_clean)}/{len(evil_tools_raw)} tools passed "
              f"({blocked_count} blocked at registration)")
        evil_available = True
    except Exception as e:
        print(f"  Evil MCP not available: {e}")

    # Detect collisions
    if evil_available:
        wazuh_names = {t["name"] for t in wazuh_tools_clean}
        evil_names  = {t["name"] for t in evil_tools_clean}
        collisions  = wazuh_names & evil_names
        if collisions:
            print(f"\n  WARNING: TOOL NAME COLLISIONS: {collisions}")

    # Fetch alert
    if custom_alert:
        alert_text = custom_alert
        print(f"\n  Using custom alert: {alert_text}")
    else:
        print(f"\n  Fetching latest alert from Wazuh...")
        try:
            alert_text = framework.call_tool(
                "orchestrator", "get_wazuh_latest_alert", {}
            )
            print(f"  Alert received ({len(alert_text)} chars)")
        except Exception as e:
            logger.error(f"Could not fetch alert: {e}")
            sys.exit(1)

    if not alert_text or not alert_text.strip():
        print("  No alerts found.")
        sys.exit(0)

    print(f"\n  Alert preview:\n  {alert_text[:250]} ...\n")
    print("  Running L1 pipeline with security framework...")

    # Triage
    triage = run_triage_agent(alert_text, framework, memory,
                               session_id=session_id)
    _section("TRIAGE", triage)

    # Validate handoff triage -> enrichment
    print(f"\n  [HANDOFF] triage -> enrichment")
    try:
        framework.validate_handoff(
            "triage_agent", "enrichment_agent", json.dumps(triage)
        )
        print(f"    severity={triage.get('severity','?')} | "
              f"threat={triage.get('threat_type','?')} | "
              f"escalate={triage.get('escalate','?')} | PASSED")
    except ValueError as e:
        print(f"    BLOCKED: {e}")
        triage = {"severity": "unknown", "error": "handoff blocked"}

    # Enrichment
    enrichment = run_enrichment_agent(alert_text, triage, framework, memory,
                                       session_id=session_id)
    _section("ENRICHMENT", enrichment)

    # Validate handoff enrichment -> response
    print(f"\n  [HANDOFF] enrichment -> response")
    try:
        framework.validate_handoff(
            "enrichment_agent", "response_agent", json.dumps(enrichment)
        )
        print(f"    agent={enrichment.get('agent_info',{}).get('name','?')} | "
              f"vulns={len(enrichment.get('vulnerabilities',[]))} | PASSED")
    except ValueError as e:
        print(f"    BLOCKED: {e}")
        enrichment = {"error": "handoff blocked"}

    # Response
    response = run_response_agent(
        alert_text, triage, enrichment, framework, memory,
        session_id=session_id
    )
    _section("RESPONSE PLAN", response)

    # [NEW] Oversight saturation check
    requires_approval = response.get("requires_human_approval", False)
    approval_allowed  = _check_oversight_saturation(requires_approval)
    if not approval_allowed:
        response["requires_human_approval"] = False
        response["_approval_suppressed"] = (
            "Approval request suppressed: oversight saturation limit reached."
        )
        logger.warning("  [OVERSIGHT] Human approval request suppressed.")

    # Summary
    print(f"\n{'='*60}")
    print(f"  Severity   : {triage.get('severity','?').upper()}")
    print(f"  False pos  : {triage.get('is_false_positive','?')}")
    print(f"  Escalate   : {'YES -> L2' if triage.get('escalate') else 'No'}")
    print(f"  Actions    : {len(response.get('recommended_actions',[]))} recommended")
    print(f"  Human appr.: {'Required' if response.get('requires_human_approval') else 'Not required'}")
    if response.get("_approval_suppressed"):
        print(f"  WARNING    : {response['_approval_suppressed']}")
    print(f"{'='*60}")

    framework.print_audit_summary()

    final = memory.stats()
    print(f"  Memory after run: {final['alerts_stored']} alerts, "
          f"{final['agents_known']} agents known\n")

    wazuh_mcp.disconnect()
    if evil_available:
        evil_mcp.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--alert",        type=str,           default=None)
    parser.add_argument("--show-memory",  action="store_true")
    parser.add_argument("--reset-memory", action="store_true")
    args = parser.parse_args()

    if args.show_memory or args.reset_memory:
        from memory.store import MemoryStore
        mem = MemoryStore(MEMORY_DIR)
        if args.reset_memory:
            mem.reset()
            print("  Memory reset.")
        else:
            show_memory(mem)
    else:
        run(custom_alert=args.alert)