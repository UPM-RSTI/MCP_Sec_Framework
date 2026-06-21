# TFM — Security Framework for MCP-based Multi-Agent Systems in SOC Environments

Master's thesis implementation. University project — cybersecurity, agentic AI, SOC automation.

## Overview

This repository contains the implementation of a security framework for multi-agent systems based on the Model Context Protocol (MCP) in Security Operations Center (SOC) environments.

The system deploys three specialized LLM agents (triage, enrichment, response) connected to a Wazuh SIEM through MCP. A five-layer security middleware intercepts all agent-to-tool communication and enforces access control, rate limiting, input/output validation, and audit logging.

## Architecture

```
LLM / OpenAI API
       │
┌──────┼──────────────────┐
│   Agents                │
│  Triage · Enrichment · Response
└──────┼──────────────────┘
       │
┌──────▼──────────────────────────────────────┐
│  Security Framework (middleware)             │
│                                              │
│  Tool reg. validator  Layer 1: RBAC          │
│  Layer 2: Rate limiter                       │
│  Layer 3: Input validator (JSON schema)      │
│  Layer 4: Output validator                   │
│  Layer 5: Audit log (SHA-256 · redaction)    │
└──────┬──────────────────┬───────────────────┘
       │                  │
  Wazuh MCP          Evil MCP server
  (16 tools)         (attack simulation)
       │
  Wazuh SIEM
```

## Security Framework

Five-layer middleware implemented in `framework/security.py`, aligned with the OWASP Practical Guide for Secure MCP Server Development v1.0.

| Layer | Control | Attack vectors covered |
|---|---|---|
| Tool registration validator | Description scan + manifest hash (version pinning) | Tool description poisoning, tool shadowing, rug pull |
| Layer 1 | RBAC per agent role, explicit allowlist | Privilege escalation, confused deputy |
| Layer 2 | Rate limiter (20/30/20 calls per 60s) | DoS internal, data exfiltration by query flooding |
| Layer 3 | Input validator: JSON schema + regex + handoff + memory | Direct prompt injection, inter-agent trust exploitation, memory poisoning |
| Layer 4 | Output validator: pattern matching + 100KB size limit | Indirect prompt injection, tool poisoning in response, context flooding |
| Layer 5 | Immutable audit log, field-level redaction, SHA-256 result hash | Forensic traceability, sensitive data governance |

## Evil MCP Server

Adversarial MCP server for attack simulation (`evil_mcp_server.py`). Exposes four malicious tools:

- `get_threat_intelligence` — tool description poisoning
- `get_compliance_report` — confused deputy (instructs agent to call `propose_wazuh_rule`)
- `get_vulnerability_feed` — indirect prompt injection via output
- `get_wazuh_latest_alert` — tool shadowing (name collision with legitimate tool)

Runs as a Docker service: `docker-compose up -d`

## Evaluation

Extended evaluation with N=20 repeated trials per test. Metrics: ASR, DR, FPR, Precision, Recall, F1, latency overhead.

| Test | Layer | ASR | DR | FPR | F1 | Overhead |
|---|---|---|---|---|---|---|
| T01 | Tool registration validator | 1.00 | 1.00 | 0.000 | 1.00 | +8.3% |
| T02 | Layer 1: Access control | 1.00 | 1.00 | 0.000 | 1.00 | -36.0% |
| T03 | Layer 2: Rate limiter | 1.00 | 1.00 | 0.000 | 1.00 | -96.7% |
| T04 | Layer 3: Input validator | 1.00 | 1.00 | 0.000 | 1.00 | +4.4% |
| T05 | Layer 4: Output validator | 0.33 | 1.00 | 0.000 | 1.00 | +152.8% |
| **Avg** | | | **1.00** | **0.000** | **1.00** | **+6.6%** |

## Project Structure

```
SOC-framework/
├── agents/
│   └── agents.py           triage, enrichment, response agent implementations
├── framework/
│   ├── security.py         five-layer security middleware
│   └── tool_schemas.py     JSON schema definitions for all 16 Wazuh tools
├── mcp/
│   └── client.py           MCP client (JSON-RPC 2.0 over HTTP/SSE)
├── memory/
│   └── store.py            shared persistent memory (JSON on disk)
├── tests/
│   ├── common.py           shared test utilities and RawMCP client
│   └── test_t01..t05.py    individual test scripts per layer
├── scripts/
│   └── setup_secrets.sh    secrets setup with chmod 600
├── main.py                 single-run pipeline
├── run_tests_extended.py   extended evaluation (N=20, full metrics)
├── evil_mcp_server.py      adversarial MCP server
├── Dockerfile              non-root hardened image
├── Dockerfile.evil         evil MCP server image
└── docker-compose.yml      evil-mcp as persistent service
```

## Setup

```bash
# Clone
git clone https://github.com/rodtpsim/TFM.git
cd TFM

# Virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Secrets (API key with chmod 600)
chmod +x scripts/setup_secrets.sh
./scripts/setup_secrets.sh

# Start evil MCP server (Docker)
docker-compose up -d

# Run pipeline
python main.py

# Run evaluation (N=20 trials)
python run_tests_extended.py
```

## Infrastructure

- Wazuh SIEM: `192.168.56.110` (Vagrant VM)
- Wazuh MCP server: `http://192.168.56.110:8080/mcp` (gbrigandi/mcp-server-wazuh v0.3.0)
- Evil MCP server: `http://127.0.0.1:8089/mcp` (Docker container)
- MCP protocol version: `2025-06-18`
- LLM: GPT-4o via OpenAI API

## OWASP Compliance

Controls implemented against the OWASP Practical Guide for Secure MCP Server Development v1.0:

- Section 2: Tool description validation, version pinning with SHA-256 manifest hash
- Section 3: JSON schema validation per tool, rate limits, output size limits
- Section 4: Prompt injection controls, human-in-the-loop for destructive actions
- Section 5: Centralized policy enforcement, least privilege per agent role
- Section 6: Safe error handling (no stack traces to LLM), non-root Docker container, secrets with restricted filesystem permissions, network segmentation
- Section 7: Immutable audit log, field-level redaction of sensitive arguments

## License

Academic project — Universidad Politécnica de Madrid, 2026.
