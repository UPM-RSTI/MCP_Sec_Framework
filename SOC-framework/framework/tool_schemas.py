"""
framework/tool_schemas.py — JSON Schema definitions for all Wazuh MCP tools.

OWASP Practical Guide for Secure MCP Server Development, Section 3:
  "Define and enforce JSON Schemas for every tool's inputs (from the model)
   and outputs (back to the model). Reject any request that doesn't match
   the expected schema."

Each entry maps tool_name -> jsonschema dict.
Validation is performed by the Input Validator (Layer 3) before any call
reaches the MCP server.
"""

TOOL_SCHEMAS: dict[str, dict] = {

    "get_wazuh_latest_alert": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },

    "get_wazuh_alert_summary": {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        "additionalProperties": False,
    },

    "get_wazuh_agents": {
        "type": "object",
        "properties": {
            "status":  {"type": "string", "enum": ["active", "disconnected", "never_connected", "pending"]},
            "name":    {"type": "string", "maxLength": 128, "pattern": "^[a-zA-Z0-9_\\-\\.]+$"},
            "ip":      {"type": "string", "pattern": "^\\d{1,3}(\\.\\d{1,3}){3}$"},
            "limit":   {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "additionalProperties": False,
    },

    "get_wazuh_agent_processes": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "pattern": "^\\d{3}$"},
            "limit":    {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "required": ["agent_id"],
        "additionalProperties": False,
    },

    "get_wazuh_agent_ports": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "pattern": "^\\d{3}$"},
            "protocol": {"type": "string", "enum": ["tcp", "udp"]},
            "state":    {"type": "string", "enum": [
                "LISTEN", "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT",
                "LISTENING", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
                "FIN_WAIT2", "LAST_ACK", "CLOSED",
            ]},
            "limit":    {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "required": ["agent_id"],
        "additionalProperties": False,
    },

    "get_wazuh_vulnerability_summary": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "pattern": "^\\d{3}$"},
            "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
            "limit":    {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "required": ["agent_id"],
        "additionalProperties": False,
    },

    "get_wazuh_critical_vulnerabilities": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "pattern": "^\\d{3}$"},
            "limit":    {"type": "integer", "minimum": 1, "maximum": 100},
        },
        "required": ["agent_id"],
        "additionalProperties": False,
    },

    "get_wazuh_rules_summary": {
        "type": "object",
        "properties": {
            "level": {"type": "integer", "minimum": 0, "maximum": 15},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "additionalProperties": False,
    },

    "get_wazuh_cluster_health": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },

    "get_wazuh_cluster_nodes": {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
        "additionalProperties": False,
    },

    "get_wazuh_weekly_stats": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },

    "get_wazuh_remoted_stats": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },

    "get_wazuh_log_collector_stats": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },

    "get_wazuh_manager_error_logs": {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "additionalProperties": False,
    },

    "search_wazuh_manager_logs": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "maxLength": 256},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "required": ["query"],
        "additionalProperties": False,
    },

    "propose_wazuh_rule": {
        "type": "object",
        "properties": {
            "rule_id":  {"type": "integer", "minimum": 100000, "maximum": 999999},
            "rule_xml": {"type": "string", "maxLength": 4096},
        },
        "required": ["rule_id", "rule_xml"],
        "additionalProperties": False,
    },
}
