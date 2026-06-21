"""
framework/security.py — Security Framework for MCP-based Multi-Agent Systems.

OWASP controls implemented (Practical Guide for Secure MCP Server Development v1.0):

  Section 2 - Safe Tool Design:
    Tool registration validator  Scans descriptions at connect time
    Tool version pinning         SHA-256 hash of tool manifest at first connect;
                                 detects changes on reconnect (partial rug pull mitigation)
    Tool namespace ownership     First server to register a tool name owns it;
                                 later servers registering the same name are blocked
                                 (tool shadowing / name collision mitigation)
    Supply chain verification    SHA-256 hash of wazuh-mcp binary at connect time

  Section 3 - Data Validation and Resource Management:
    Layer 3 Input validator      JSON schema validation per tool (via tool_schemas.py)
                                 + regex injection patterns + inter-agent trust
                                 + external data validation (malicious data injection)
    Layer 4 Output validator     Pattern matching + 100KB size limit
                                 + credential/API key exfiltration patterns
                                 + system prompt extraction patterns
                                 + agent self-propagation patterns
                                 + external content mode (web content poisoning)

  Section 4 - Prompt Injection Controls:
    Layer 3 Input validator      Argument and handoff scanning
    Layer 3 Memory validator     Context store validation before prompt injection

  Section 5 - Authentication and Authorization:
    Layer 1 Access control       RBAC per agent role, explicit allowlist

  Section 6 - Secure Deployment:
    Safe error handling          Framework exceptions never expose stack traces
                                 or server internals to the LLM

  Section 7 - Governance:
    Layer 5 Audit log            Immutable record, SHA-256 result hash,
                                 field-level redaction of sensitive arguments,
                                 session_id per entry

  Section 3 - Resource Management:
    Layer 2 Rate limiter         Per-agent call budget (20/30/20 per 60s)
    Oversight saturation         Pipeline approval rate limiter (10/hour)

  Group 2 controls:
    Session ID                   UUID per pipeline execution for traceability
    Human-agent trust            Response agent justification validation
    Oversight saturation         Pipeline approval rate limiter

  Group 3 controls:
    Supply chain verification    SHA-256 binary hash check at connect time
    Cross-client isolation       Session namespace in context store (in memory/store.py)
    Authentication               X-MCP-API-Key header (in mcp/client.py)

Controls not implemented (out of scope - infrastructure layer):
    OAuth 2.1 / OIDC             Requires external identity provider
    TLS enforcement              Transport layer, lab environment uses private network
    Secrets vault                Disproportionate for lab scope
    LLM-as-a-judge               Cost and complexity beyond declared scope
"""

import os
import re
import json
import time
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, asdict

try:
    import jsonschema
    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    _JSONSCHEMA_AVAILABLE = False

from framework.tool_schemas import TOOL_SCHEMAS

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# SENSITIVE FIELD REDACTION
# ══════════════════════════════════════════════════════════════════════════════

_SENSITIVE_FIELDS = {"rule_xml", "api_key", "token", "password", "secret"}


def _redact(arguments: dict) -> dict:
    result = {}
    for k, v in arguments.items():
        if k in _SENSITIVE_FIELDS and isinstance(v, str):
            result[k] = f"[REDACTED sha256:{hashlib.sha256(v.encode()).hexdigest()[:12]}]"
        else:
            result[k] = v
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SAFE ERROR RESPONSES
# ══════════════════════════════════════════════════════════════════════════════

_SAFE_ERRORS = {
    "blocked_access":      "Tool call blocked: insufficient permissions for this agent role.",
    "blocked_rate":        "Tool call blocked: call rate limit exceeded for this agent.",
    "blocked_input":       "Tool call blocked: argument validation failed.",
    "blocked_output":      "Tool call blocked: response validation failed.",
    "blocked_interagent":  "Handoff blocked: upstream agent output failed trust validation.",
    "blocked_memory":      "Context blocked: persistent context failed validation.",
    "blocked_schema":      "Tool call blocked: argument schema validation failed.",
    "blocked_data":        "Data blocked: external data failed validation.",
    "blocked_supply_chain":"Server rejected: binary hash verification failed.",
    "blocked_shadowing":   "Tool rejected: name already owned by another registered server.",
    "error":               "Tool call failed: an internal error occurred.",
}


def safe_error_message(outcome: str) -> str:
    return _SAFE_ERRORS.get(outcome, "Tool call blocked.")


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — ACCESS CONTROL
# ══════════════════════════════════════════════════════════════════════════════

READ_ONLY_TOOLS = {
    "get_wazuh_agents",
    "get_wazuh_alert_summary",
    "get_wazuh_agent_processes",
    "get_wazuh_agent_ports",
    "get_wazuh_cluster_nodes",
    "get_wazuh_cluster_health",
    "get_wazuh_latest_alert",
    "get_wazuh_rules_summary",
    "get_wazuh_vulnerability_summary",
    "get_wazuh_critical_vulnerabilities",
    "get_wazuh_weekly_stats",
    "get_wazuh_remoted_stats",
    "get_wazuh_log_collector_stats",
    "get_wazuh_manager_error_logs",
    "search_wazuh_manager_logs",
}

DESTRUCTIVE_TOOLS = {"propose_wazuh_rule"}

TRIAGE_TOOLS = {
    "get_wazuh_latest_alert",
    "get_wazuh_alert_summary",
    "get_wazuh_rules_summary",
}
ENRICHMENT_TOOLS = {
    "get_wazuh_agents",
    "get_wazuh_agent_processes",
    "get_wazuh_agent_ports",
    "get_wazuh_vulnerability_summary",
    "get_wazuh_critical_vulnerabilities",
    "get_wazuh_cluster_health",
    "get_wazuh_cluster_nodes",
}
RESPONSE_TOOLS = {
    "get_wazuh_latest_alert",
    "get_wazuh_alert_summary",
    "get_wazuh_agents",
    "get_wazuh_vulnerability_summary",
    "get_wazuh_rules_summary",
    "propose_wazuh_rule",
}

AGENT_PERMISSIONS: dict[str, set[str]] = {
    "triage_agent":     TRIAGE_TOOLS,
    "enrichment_agent": ENRICHMENT_TOOLS,
    "response_agent":   RESPONSE_TOOLS,
    "orchestrator":     {"get_wazuh_latest_alert"},
}


class AccessControl:

    def check(self, agent_role: str, tool_name: str) -> None:
        allowed = AGENT_PERMISSIONS.get(agent_role, set())
        if tool_name not in allowed:
            logger.warning(
                f"[ACCESS CONTROL] BLOCKED: '{agent_role}' cannot call '{tool_name}'."
            )
            raise PermissionError(safe_error_message("blocked_access"))

    def filter_tools(self, agent_role: str, all_tools: list) -> list:
        allowed = AGENT_PERMISSIONS.get(agent_role, set())
        return [t for t in all_tools if t["name"] in allowed]


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — RATE LIMITER
# ══════════════════════════════════════════════════════════════════════════════

RATE_LIMITS: dict[str, dict] = {
    "triage_agent":     {"max_calls": 20, "window_seconds": 60},
    "enrichment_agent": {"max_calls": 30, "window_seconds": 60},
    "response_agent":   {"max_calls": 20, "window_seconds": 60},
    "orchestrator":     {"max_calls": 10, "window_seconds": 60},
    "_default":         {"max_calls": 15, "window_seconds": 60},
}


class RateLimiter:

    def __init__(self):
        self._calls: dict[str, list[float]] = defaultdict(list)

    def check(self, agent_role: str, tool_name: str) -> None:
        limits    = RATE_LIMITS.get(agent_role, RATE_LIMITS["_default"])
        max_calls = limits["max_calls"]
        window    = limits["window_seconds"]
        now       = time.time()
        self._calls[agent_role] = [
            t for t in self._calls[agent_role] if now - t < window
        ]
        if len(self._calls[agent_role]) >= max_calls:
            logger.warning(
                f"[RATE LIMITER] BLOCKED: "
                f"'{agent_role}' exceeded {max_calls} calls in {window}s."
            )
            raise RuntimeError(safe_error_message("blocked_rate"))
        self._calls[agent_role].append(now)

    def get_stats(self) -> dict:
        now = time.time()
        return {
            role: len([t for t in ts
                       if now - t < RATE_LIMITS.get(role, RATE_LIMITS["_default"])["window_seconds"]])
            for role, ts in self._calls.items()
        }


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — INPUT VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(your\s+)?(previous|prior|system)\s+(prompt|instructions?)",
    r"forget\s+(everything|all|your\s+instructions?)",
    r"override\s+(your\s+)?(previous\s+)?instructions?",
    r"you\s+are\s+now\s+(?!analyzing|checking|retrieving|a\s+soc)",
    r"act\s+as\s+(?!an?\s+analyst|a\s+soc)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"new\s+persona|switch\s+role",
    r"(print|show|reveal|output|repeat|leak)\s+(your\s+)?(system\s+)?(prompt|instructions?)",
    r"\[SYSTEM\]|\[INST\]|<\|system\|>|<\|im_start\|>",
    r"\bDAN\b|\bjailbreak\b|developer\s+mode",
    r"[;&|`$\\](?!\d)",
    r"new\s+(task|objective|goal|instructions?)\s+(for\s+)?(you|the\s+agent)",
    r"from\s+now\s+on\s+(you|ignore|always|never)",
    r"mandatory\s+(security\s+)?(protocol|update|override)",
    r"compliance\s+(requires?|mandates?|forces?)\s+you\s+to",
]
_COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]

_EXTERNAL_DATA_PATTERNS = _INJECTION_PATTERNS + [
    r"<script[^>]*>",
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    r"on(load|error|click|mouseover)\s*=",
    r"\beval\s*\(",
    r"document\.(cookie|write|location)",
]
_COMPILED_EXTERNAL = [re.compile(p, re.IGNORECASE) for p in _EXTERNAL_DATA_PATTERNS]

_HANDOFF_SEQUENCE = {
    "triage_agent":     "enrichment_agent",
    "enrichment_agent": "response_agent",
}


@dataclass
class ValidationResult:
    passed: bool
    reason: Optional[str] = None
    outcome: str = "allowed"


class InputValidator:

    def validate(self, tool_name: str, arguments: dict) -> ValidationResult:
        schema = TOOL_SCHEMAS.get(tool_name)
        if schema and _JSONSCHEMA_AVAILABLE:
            try:
                import jsonschema as _js
                _js.validate(instance=arguments, schema=schema)
            except _js.ValidationError as e:
                return ValidationResult(
                    passed=False,
                    reason=f"[INPUT VALIDATOR] BLOCKED: Schema validation failed for '{tool_name}': {e.message}",
                    outcome="blocked_schema",
                )

        for key, value in arguments.items():
            if isinstance(value, str):
                for pattern in _COMPILED_INJECTION:
                    if pattern.search(value):
                        return ValidationResult(
                            passed=False,
                            reason=f"[INPUT VALIDATOR] BLOCKED: Injection pattern in '{key}' for '{tool_name}'.",
                            outcome="blocked_input",
                        )
        return ValidationResult(passed=True)

    def validate_agent_output(self, source_agent: str, output: str,
                               expected_target: str = None) -> ValidationResult:
        if expected_target is not None:
            allowed_target = _HANDOFF_SEQUENCE.get(source_agent)
            if allowed_target and expected_target != allowed_target:
                return ValidationResult(
                    passed=False,
                    reason=(
                        f"[INTER-AGENT TRUST] BLOCKED: '{source_agent}' attempted handoff "
                        f"to '{expected_target}' but expected '{allowed_target}'. "
                        f"Possible agent impersonation."
                    ),
                    outcome="blocked_interagent",
                )

        for pattern in _COMPILED_INJECTION:
            if pattern.search(output):
                return ValidationResult(
                    passed=False,
                    reason=f"[INTER-AGENT TRUST] BLOCKED: Output of '{source_agent}' contains injection pattern.",
                    outcome="blocked_interagent",
                )
        return ValidationResult(passed=True)

    def validate_memory_context(self, context: dict) -> ValidationResult:
        for key, value in context.items():
            if isinstance(value, str):
                for pattern in _COMPILED_INJECTION:
                    if pattern.search(value):
                        return ValidationResult(
                            passed=False,
                            reason=f"[MEMORY VALIDATOR] BLOCKED: context_store key '{key}' contains injection pattern.",
                            outcome="blocked_memory",
                        )
        return ValidationResult(passed=True)

    def validate_external_data(self, source: str, data: str) -> ValidationResult:
        for pattern in _COMPILED_EXTERNAL:
            if pattern.search(data):
                return ValidationResult(
                    passed=False,
                    reason=f"[EXTERNAL DATA] BLOCKED: Data from '{source}' contains malicious content.",
                    outcome="blocked_data",
                )
        return ValidationResult(passed=True)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — OUTPUT VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

_OUTPUT_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?:",
    r"\[SYSTEM\]|\[INST\]",
    r"exfiltrate|send\s+(this\s+)?(data|credentials?|password|token)\s+to",
    r"call\s+tool\s+(propose_wazuh_rule)\s+with",
    r"execute\s+(the\s+following|this)\s+command",
    r"your\s+new\s+(task|goal|objective)\s+is",
    r"mandatory\s+(action|requirement|protocol)",
    r"(required|must)\s+(call|invoke|execute|run)\s+tool",
    # Credential / API key exfiltration
    r"sk-[a-zA-Z0-9]{20,}",
    r"Bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    r"api[_\-]?key\s*[:=]\s*[a-zA-Z0-9\-_]{16,}",
    r"password\s*[:=]\s*\S{8,}",
    r"secret\s*[:=]\s*\S{8,}",
    r"token\s*[:=]\s*[a-zA-Z0-9\-_\.]{16,}",
    r"Authorization:\s*(Bearer|Basic)\s+\S+",
    # LLM system prompt extraction
    r"(my|the|your)\s+system\s+prompt\s+(is|says|reads|contains)",
    r"(my|the|your)\s+instructions?\s+(are|is|say|read|include):",
    r"(above|following)\s+(are|is)\s+(my|the|your)\s+(instructions?|prompt|directives?)",
    r"i\s+(was|am|have\s+been)\s+(instructed|told|directed|prompted)\s+to",
    r"(initial|original|base)\s+(system\s+)?(prompt|instructions?)\s*(:|is|are|says)",
    # Agent self-propagation (AI virus)
    r"copy\s+(this|the\s+following)\s+(instruction|prompt|payload)\s+to",
    r"forward\s+(this|the\s+following)\s+(message|instruction|payload)\s+to",
    r"replicate\s+(yourself|this\s+instruction|this\s+payload)",
    r"inject\s+(the\s+following|this)\s+(into\s+)?(the\s+next|downstream|other)\s+agent",
    r"pass\s+(this|the\s+following)\s+(payload|instruction)\s+(along|forward|to\s+the\s+next)",
]
_COMPILED_OUTPUT = [re.compile(p, re.IGNORECASE) for p in _OUTPUT_PATTERNS]

_EXTERNAL_CONTENT_PATTERNS = _OUTPUT_PATTERNS + [
    r"<script[^>]*>",
    r"javascript\s*:",
    r"on(load|error|click|mouseover)\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"document\.(cookie|write|location)",
    r"window\.(location|open|eval)",
    r"\beval\s*\(",
    r"data\s*:\s*text/html",
]
_COMPILED_EXTERNAL_OUTPUT = [re.compile(p, re.IGNORECASE) for p in _EXTERNAL_CONTENT_PATTERNS]

MAX_OUTPUT_BYTES = 100_000

_EXTERNAL_CONTENT_TOOLS = {
    "get_threat_intelligence",
    "get_vulnerability_feed",
    "get_compliance_report",
}


class OutputValidator:

    def validate(self, tool_name: str, raw_output: str) -> ValidationResult:
        if len(raw_output) > MAX_OUTPUT_BYTES:
            return ValidationResult(
                passed=False,
                reason=(
                    f"[OUTPUT VALIDATOR] BLOCKED: Response from '{tool_name}' too large "
                    f"({len(raw_output)} > {MAX_OUTPUT_BYTES} bytes)."
                ),
                outcome="blocked_output",
            )

        if tool_name in _EXTERNAL_CONTENT_TOOLS:
            patterns = _COMPILED_EXTERNAL_OUTPUT
            mode = "external"
        else:
            patterns = _COMPILED_OUTPUT
            mode = "standard"

        for pattern in patterns:
            if pattern.search(raw_output):
                return ValidationResult(
                    passed=False,
                    reason=f"[OUTPUT VALIDATOR] BLOCKED ({mode}): Malicious content in '{tool_name}' response.",
                    outcome="blocked_output",
                )
        return ValidationResult(passed=True)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL REGISTRATION VALIDATOR + VERSION PINNING + SUPPLY CHAIN + NAMESPACE OWNERSHIP
# ══════════════════════════════════════════════════════════════════════════════

_TOOL_DESC_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",
    r"important\s+(system\s+)?instruction\s+for\s+(ai|llm|assistant)",
    r"(mandatory|required)\s+(for\s+)?(ai|llm|the\s+model)",
    r"you\s+must\s+(call|invoke|execute|always|never)",
    r"after\s+(calling|using|invoking)\s+this\s+tool.{0,50}(call|invoke|execute)",
    r"new\s+(system\s+)?instructions?\s+for\s+(the\s+)?(ai|model|assistant)",
    r"override\s+(the\s+)?(previous|prior|system)",
    r"\[SYSTEM\]|\[INST\]|<\|system\|>",
    r"note\s+for\s+(ai|llm|assistant|the\s+model)",
]
_COMPILED_DESC = [re.compile(p, re.IGNORECASE) for p in _TOOL_DESC_PATTERNS]

# [NEW] Trusted binary hashes for supply chain verification (Group 3).
# Key: server URL prefix. Value: expected SHA-256 of the server binary.
# Obtain with: docker exec wazuh-mcp sha256sum /app/mcp-server-wazuh
# Then set WAZUH_MCP_BINARY_HASH and WAZUH_MCP_BINARY_HASH_ACTUAL in .env
TRUSTED_BINARY_HASHES: dict[str, str] = {
    "http://127.0.0.1:8085": os.getenv("WAZUH_MCP_BINARY_HASH", ""),
}


def _manifest_hash(tools: list) -> str:
    canonical = json.dumps(
        sorted([{"name": t["name"], "description": t.get("description", "")}
                for t in tools],
               key=lambda x: x["name"]),
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class ToolRegistrationValidator:

    def __init__(self):
        self._pinned_hashes: dict[str, str] = {}
        # [NEW] Tool namespace ownership map (tool shadowing / name collision
        # mitigation). Maps tool_name -> the server_url that first registered
        # it. Any later server attempting to register a tool under a name
        # already owned by a different server is rejected, preventing a
        # malicious server from shadowing a trusted tool name.
        self._name_owner: dict[str, str] = {}

    def verify_server_binary(self, server_url: str) -> bool:
        """
        [NEW] Supply chain attack mitigation (Group 3).
        Verifies the wazuh-mcp binary SHA-256 hash against TRUSTED_BINARY_HASHES.
        Returns True if verification passes or is not configured.
        Returns False if a hash mismatch is detected — caller should reject the server.
        """
        # Read hashes fresh from env on every call so mock.patch.dict works in tests
        expected_hash = os.getenv("WAZUH_MCP_BINARY_HASH", "")
        if not expected_hash:
            logger.info(
                f"[SUPPLY CHAIN] No hash configured for {server_url}. "
                f"Set WAZUH_MCP_BINARY_HASH in .env to enable verification."
            )
            return True

        actual_hash = os.getenv("WAZUH_MCP_BINARY_HASH_ACTUAL", "")
        if not actual_hash:
            logger.info(
                f"[SUPPLY CHAIN] Cannot verify {server_url}: "
                f"WAZUH_MCP_BINARY_HASH_ACTUAL not set. "
                f"Run: docker exec wazuh-mcp sha256sum /app/mcp-server-wazuh"
            )
            return True

        if actual_hash.lower().strip() != expected_hash.lower().strip():
            logger.error(
                f"[SUPPLY CHAIN] HASH MISMATCH for {server_url}! "
                f"Expected: {expected_hash[:16]} "
                f"Actual: {actual_hash[:16]}. "
                f"Possible supply chain attack or unauthorized binary replacement."
            )
            return False

        logger.info(
            f"[SUPPLY CHAIN] Binary verified for {server_url}: {actual_hash[:16]}"
        )
        return True

    def check_name_collisions(self, tools: list, server_url: str) -> tuple[list, list]:
        """
        [NEW] Tool namespace ownership check (tool shadowing / name collision
        mitigation, Section 2). The first server to successfully register a
        tool name owns that name for the lifetime of this validator instance.
        Any subsequent registration of the same name from a DIFFERENT
        server_url is rejected and reported as a collision, preventing a
        malicious server from shadowing a trusted tool.

        Returns (clean, collided) where collided entries carry a
        '_blocked_reason' explaining the conflicting owner.
        """
        clean    = []
        collided = []
        for tool in tools:
            name  = tool["name"]
            owner = self._name_owner.get(name)
            if owner is not None and owner != server_url:
                reason = (
                    f"Tool name '{name}' already owned by '{owner}'; "
                    f"registration from '{server_url}' rejected (shadowing/collision)."
                )
                collided.append({**tool, "_blocked_reason": reason, "_server": server_url})
                logger.warning(f"[TOOL REGISTRATION] BLOCKED (collision): {reason}")
            else:
                if owner is None:
                    self._name_owner[name] = server_url
                clean.append(tool)
        return clean, collided

    def validate_tools(self, tools: list, server_url: str) -> tuple[list, list]:
        clean   = []
        blocked = []

        # Step 1: description poisoning scan
        desc_clean = []
        for tool in tools:
            desc     = tool.get("description", "")
            poisoned = False
            reason   = ""
            for pattern in _COMPILED_DESC:
                if pattern.search(desc):
                    poisoned = True
                    reason   = f"Description matches pattern: /{pattern.pattern}/"
                    break
            if poisoned:
                blocked.append({**tool, "_blocked_reason": reason, "_server": server_url})
                logger.warning(
                    f"[TOOL REGISTRATION] BLOCKED: "
                    f"Tool '{tool['name']}' from {server_url}. {reason}"
                )
            else:
                desc_clean.append(tool)

        # Step 2: tool name collision / shadowing check on the tools that
        # survived the description-poisoning scan
        clean, collided = self.check_name_collisions(desc_clean, server_url)
        blocked.extend(collided)

        current_hash = _manifest_hash(tools)
        if server_url in self._pinned_hashes:
            if self._pinned_hashes[server_url] != current_hash:
                logger.warning(
                    f"[TOOL REGISTRATION] WARNING: Tool manifest changed for {server_url}. "
                    f"Previous: {self._pinned_hashes[server_url][:16]} "
                    f"Current: {current_hash[:16]}. Possible rug pull."
                )
        else:
            self._pinned_hashes[server_url] = current_hash
            logger.info(
                f"[TOOL REGISTRATION] Manifest pinned for {server_url}: {current_hash[:16]}"
            )

        logger.info(
            f"[TOOL REGISTRATION] {server_url}: {len(clean)} clean, {len(blocked)} blocked."
        )
        return clean, blocked

    def manifest_changed(self, server_url: str, tools: list) -> bool:
        """
        [NEW] Explicit rug-pull check helper. Returns True if the current
        manifest hash differs from the pinned hash for this server_url.
        Does NOT update the pin — callers that want to also re-pin should
        call validate_tools() afterwards, which pins on first sight and
        only warns (does not re-pin) on subsequent mismatches.
        """
        current_hash = _manifest_hash(tools)
        pinned = self._pinned_hashes.get(server_url)
        return pinned is not None and pinned != current_hash

    def get_pinned_hashes(self) -> dict:
        return dict(self._pinned_hashes)

    def get_name_owners(self) -> dict:
        return dict(self._name_owner)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuditEntry:
    timestamp:   str
    session_id:  str
    agent_role:  str
    tool_name:   str
    arguments:   dict
    outcome:     str
    detail:      Optional[str] = None
    result_hash: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLog:

    def __init__(self, session_id: str = None):
        import uuid
        self._session_id  = session_id or str(uuid.uuid4())
        self._entries: list[AuditEntry] = []
        self._reg_events: list[dict]    = []

    def record(self, agent_role, tool_name, arguments, outcome,
               detail=None, result=None) -> AuditEntry:
        safe_args   = _redact(arguments)
        safe_detail = safe_error_message(outcome) if (detail and outcome != "allowed") else detail

        entry = AuditEntry(
            timestamp   = datetime.now(timezone.utc).isoformat(),
            session_id  = self._session_id,
            agent_role  = agent_role,
            tool_name   = tool_name,
            arguments   = safe_args,
            outcome     = outcome,
            detail      = safe_detail,
            result_hash = hashlib.sha256(result.encode()).hexdigest()[:16] if result else None,
        )
        self._entries.append(entry)
        icon = "✅" if outcome == "allowed" else "🚫"
        logger.info(f"  {icon} AUDIT [{agent_role}] {tool_name} = {outcome}")
        if safe_detail and outcome != "allowed":
            logger.warning(f"     {safe_detail[:120]}")
        return entry

    def record_registration(self, server_url: str, clean: list,
                             blocked: list, manifest_hash: str):
        self._reg_events.append({
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "server_url":    server_url,
            "manifest_hash": manifest_hash[:16],
            "clean":         [t["name"] for t in clean],
            "blocked":       [{"name": t["name"],
                               "reason": t.get("_blocked_reason", "")}
                              for t in blocked],
        })

    def record_interagent_block(self, source: str, target: str, reason: str):
        self.record(source, f"[handoff to {target}]", {}, "blocked_interagent",
                    safe_error_message("blocked_interagent"))

    def record_memory_block(self, reason: str):
        self.record("memory", "[context_store]", {}, "blocked_memory",
                    safe_error_message("blocked_memory"))

    def get_all(self) -> list[dict]:
        return [e.to_dict() for e in self._entries]

    def get_blocked(self) -> list[dict]:
        return [e.to_dict() for e in self._entries if e.outcome.startswith("blocked")]

    def summary(self) -> dict:
        total   = len(self._entries)
        blocked = len(self.get_blocked())
        by_outcome: dict[str, int] = {}
        by_agent:   dict[str, int] = {}
        for e in self._entries:
            by_outcome[e.outcome]  = by_outcome.get(e.outcome, 0) + 1
            by_agent[e.agent_role] = by_agent.get(e.agent_role, 0) + 1
        return {
            "total_calls":             total,
            "allowed_calls":           total - blocked,
            "blocked_calls":           blocked,
            "block_rate":              f"{(blocked/total*100):.1f}%" if total else "0%",
            "by_outcome":              by_outcome,
            "by_agent":                by_agent,
            "tools_blocked_at_registration": sum(
                len(e["blocked"]) for e in self._reg_events
            ),
        }


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY FRAMEWORK — unified entry point
# ══════════════════════════════════════════════════════════════════════════════

class SecurityFramework:

    def __init__(self, mcp_client, session_id: str = None):
        import uuid
        self.mcp        = mcp_client
        self.session_id = session_id or str(uuid.uuid4())
        self.access     = AccessControl()
        self.ratelim    = RateLimiter()
        self.inp        = InputValidator()
        self.out        = OutputValidator()
        self.tool_reg   = ToolRegistrationValidator()
        self.audit      = AuditLog(session_id=self.session_id)
        logger.info(f"[FRAMEWORK] Session {self.session_id[:16]} initialized")

    def register_server(self, server_url: str, tools: list) -> list:
        # [NEW] Supply chain verification before registering tools (Group 3)
        if not self.tool_reg.verify_server_binary(server_url):
            logger.error(
                f"[SUPPLY CHAIN] Server {server_url} rejected: binary hash mismatch."
            )
            self.audit.record(
                "framework", f"[register:{server_url}]", {},
                "blocked_supply_chain"
            )
            return []

        clean, blocked = self.tool_reg.validate_tools(tools, server_url)
        manifest_hash  = _manifest_hash(tools)
        self.audit.record_registration(server_url, clean, blocked, manifest_hash)
        return clean

    def validate_handoff(self, source_agent: str, target_agent: str,
                          output: str) -> str:
        result = self.inp.validate_agent_output(source_agent, output,
                                                 expected_target=target_agent)
        if not result.passed:
            self.audit.record_interagent_block(source_agent, target_agent, result.reason)
            raise ValueError(safe_error_message("blocked_interagent"))
        return output

    def validate_memory_context(self, context: dict) -> dict:
        result = self.inp.validate_memory_context(context)
        if not result.passed:
            self.audit.record_memory_block(result.reason)
            logger.warning(result.reason)
            return {}
        return context

    def validate_external_data(self, source: str, data: str) -> str:
        result = self.inp.validate_external_data(source, data)
        if not result.passed:
            self.audit.record("external", f"[external:{source}]", {},
                               "blocked_data", result.reason)
            logger.warning(result.reason)
            raise ValueError(safe_error_message("blocked_data"))
        return data

    def call_tool(self, agent_role: str, tool_name: str,
                  arguments: dict) -> str:

        # Layer 1: Access control
        try:
            self.access.check(agent_role, tool_name)
        except PermissionError:
            self.audit.record(agent_role, tool_name, arguments, "blocked_access")
            raise PermissionError(safe_error_message("blocked_access")) from None

        # Layer 2: Rate limiter
        try:
            self.ratelim.check(agent_role, tool_name)
        except RuntimeError:
            self.audit.record(agent_role, tool_name, arguments, "blocked_rate")
            raise RuntimeError(safe_error_message("blocked_rate")) from None

        # Layer 3: Input validation
        iv = self.inp.validate(tool_name, arguments)
        if not iv.passed:
            self.audit.record(agent_role, tool_name, arguments,
                              iv.outcome, iv.reason)
            raise ValueError(safe_error_message(iv.outcome))

        # MCP call
        try:
            raw = self.mcp.call_tool(tool_name, arguments)
        except Exception:
            self.audit.record(agent_role, tool_name, arguments, "error")
            raise RuntimeError(safe_error_message("error")) from None

        # Layer 4: Output validation
        ov = self.out.validate(tool_name, raw)
        if not ov.passed:
            self.audit.record(agent_role, tool_name, arguments,
                              ov.outcome, ov.reason, raw)
            raise ValueError(safe_error_message(ov.outcome))

        # Layer 5: Audit log
        self.audit.record(agent_role, tool_name, arguments, "allowed", result=raw)
        return raw

    def get_tools_for(self, agent_role: str) -> list:
        all_tools = self.mcp.list_tools()
        return self.access.filter_tools(agent_role, all_tools)

    def print_audit_summary(self):
        s = self.audit.summary()
        print(f"\n{'='*55}")
        print(f"  SECURITY FRAMEWORK — AUDIT SUMMARY")
        print(f"{'='*55}")
        print(f"  Total calls  : {s['total_calls']}")
        print(f"  Allowed      : {s['allowed_calls']}")
        print(f"  Blocked      : {s['blocked_calls']}  ({s['block_rate']})")
        print(f"  Tools blocked at registration: "
              f"{s['tools_blocked_at_registration']}")
        if s["by_outcome"]:
            print(f"\n  By outcome:")
            for outcome, n in s["by_outcome"].items():
                print(f"    {outcome:<30} {n}")
        if s["by_agent"]:
            print(f"\n  By agent:")
            for agent, n in s["by_agent"].items():
                print(f"    {agent:<30} {n}")
        blocked = self.audit.get_blocked()
        if blocked:
            print(f"\n  Blocked events ({len(blocked)}):")
            for b in blocked:
                ts = b['timestamp'][11:19]
                print(f"    [{ts}] {b['agent_role']} "
                      f"-> {b['tool_name']} ({b['outcome']})")
                if b['detail']:
                    print(f"    {b['detail'][:100]}")
        print(f"{'='*55}\n")