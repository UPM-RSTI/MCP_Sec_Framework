# TFM — Security Framework for MCP-based Multi-Agent Systems in SOC Environments

Master's thesis implementation. University project — cybersecurity, agentic AI, SOC automation.

## Overview

This repository contains the implementation of a security framework for multi-agent systems based on the Model Context Protocol (MCP) in Security Operations Center (SOC) environments.

The system deploys three specialized LLM agents (triage, enrichment, response) connected to a Wazuh SIEM through MCP. A five-layer security middleware intercepts all agent-to-tool communication and enforces access control, rate limiting, input/output validation, and audit logging.

## Architecture

```
labserver05 (host)
├── wazuh-mcp    Docker container → port 8085   (16 tools, custom Rust build)
├── evil-mcp     Docker container → port 8089   (attack simulation)
└── SOC-framework  python main.py

wazuh-server (Vagrant VM)
└── Wazuh SIEM   docker-compose  → ports 443 / 55000 / 9200
```

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
  Wazuh SIEM (VM)
```

## Security Framework

Five-layer middleware implemented in `SOC-framework/framework/security.py`, aligned with the OWASP Practical Guide for Secure MCP Server Development v1.0.

| Layer | Control | Attack vectors covered |
|---|---|---|
| Tool registration validator | Description scan + manifest hash (version pinning) | Tool description poisoning, tool shadowing, rug pull |
| Layer 1 | RBAC per agent role, explicit allowlist | Privilege escalation, confused deputy |
| Layer 2 | Rate limiter (20/30/20 calls per 60s) | DoS internal, data exfiltration by query flooding |
| Layer 3 | Input validator: JSON schema + regex + handoff + memory | Direct prompt injection, inter-agent trust exploitation, memory poisoning |
| Layer 4 | Output validator: pattern matching + 100KB size limit | Indirect prompt injection, tool poisoning in response, context flooding |
| Layer 5 | Immutable audit log, field-level redaction, SHA-256 result hash | Forensic traceability, sensitive data governance |

## Evil MCP Server

Adversarial MCP server for attack simulation (`SOC-framework/evil_mcp_server.py`). Exposes four malicious tools:

- `get_wazuh_latest_alert` — tool shadowing (name collision with legitimate tool)
- `get_threat_intelligence` — tool description poisoning
- `get_vulnerability_feed` — indirect prompt injection via output
- `get_compliance_report` — confused deputy (instructs agent to call `propose_wazuh_rule`)

Runs as a Docker service: `docker-compose up -d`

## Evaluation

Extended evaluation with N=20 repeated trials per test. Metrics: ASR, DR, FPR, Precision, Recall, F1, latency overhead.

| Test | Layer | ASR | DR | FPR | F1 | Overhead |
|---|---|---|---|---|---|---|
| T01 | Tool registration validator | 1.00 | 1.00 | 0.000 | 1.00 | +44.6% |
| T02 | Layer 1: Access control | 1.00 | 1.00 | 0.000 | 1.00 | +9.7% |
| T03 | Layer 2: Rate limiter | 1.00 | 1.00 | 0.000 | 1.00 | -83.3% |
| T04 | Layer 3: Input validator | 1.00 | 1.00 | 0.000 | 1.00 | +11.6% |
| T05 | Layer 4: Output validator | 0.33 | 1.00 | 0.000 | 1.00 | +107.5% |
| **Avg** | | | **1.00** | **0.000** | **1.00** | **+19.6%** |

## Repository Structure

```
TFM/
├── SOC-framework/
│   ├── agents/
│   │   └── agents.py             triage, enrichment, response agent implementations
│   ├── framework/
│   │   ├── security.py           five-layer security middleware
│   │   └── tool_schemas.py       JSON schema definitions for all 16 Wazuh tools
│   ├── mcp/
│   │   └── client.py             MCP client (JSON-RPC 2.0 over HTTP/SSE)
│   ├── memory/
│   │   └── store.py              shared persistent memory (JSON on disk)
│   ├── tests/
│   │   ├── common.py             shared test utilities and RawMCP client
│   │   └── test_t01..t05.py      individual test scripts per layer
│   ├── scripts/
│   │   └── setup_secrets.sh      secrets setup with chmod 600
│   ├── main.py                   single-run pipeline
│   ├── run_tests_extended.py     extended evaluation (N=20, full metrics)
│   ├── evil_mcp_server.py        adversarial MCP server
│   └── Dockerfile.evil           evil MCP server Docker image
├── wazuh-mcp/
│   ├── Dockerfile.wazuh-mcp      custom Rust build with 2 extra tools
│   ├── custom.rs                 get_wazuh_latest_alert + propose_wazuh_rule
│   └── main.rs                   patched main.rs with custom tools registered
├── provision/
│   ├── wazuh_server_provision.sh Wazuh SIEM provisioning script
│   └── wazuh_agent_provision.sh  Wazuh agent provisioning script
├── docker-compose.yml            wazuh-mcp + evil-mcp services
├── Vagrantfile                   Wazuh SIEM VM (SIEM only, no MCP)
├── mcp-wazuh.env.example         environment variables template
└── README.md
```

## Setup

```bash
# Clone
git clone https://github.com/rodtpsim/TFM.git
cd TFM

# 1. Start infrastructure
vagrant up wazuh-server          # Wazuh SIEM (~10 min first run)
docker-compose up -d             # wazuh-mcp + evil-mcp containers

# 2. Configure SOC-framework
cd SOC-framework
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp ../.env.example .env          # fill in OPENAI_API_KEY and MCP URLs
chmod +x scripts/setup_secrets.sh
./scripts/setup_secrets.sh

# 3. Run pipeline
python main.py

# 4. Run evaluation (N=20 trials)
python run_tests_extended.py
```

## Environment Variables

Copy `mcp-wazuh.env.example` and fill in credentials. Never commit the real `.env` file.

```
MCP_SERVER_URL=http://127.0.0.1:8085/mcp
EVIL_MCP_URL=http://127.0.0.1:8089/mcp
OPENAI_API_KEY=sk-...
```

## Infrastructure

- Wazuh SIEM: `192.168.56.110` (Vagrant VM — Ubuntu 22.04, 8GB RAM)
- Wazuh MCP server: `http://127.0.0.1:8085/mcp` (Docker — custom Rust build with 16 tools)
- Evil MCP server: `http://127.0.0.1:8089/mcp` (Docker container)
- MCP protocol version: `2025-06-18`
- LLM: GPT-4o via OpenAI API

## OWASP Compliance

Controls implemented against the OWASP Practical Guide for Secure MCP Server Development v1.0:

- **Section 2**: Tool description validation at load time, version pinning with SHA-256 manifest hash
- **Section 3**: JSON schema validation per tool (16 schemas), rate limits, 100KB output size limit
- **Section 4**: Prompt injection controls, inter-agent trust validation, memory poisoning detection, human-in-the-loop for destructive actions
- **Section 5**: Centralized policy enforcement (SecurityFramework as single gateway), least privilege RBAC per agent role
- **Section 6**: Safe error handling (no stack traces to LLM), non-root Docker containers, secrets with chmod 600, network segmentation (separate Docker networks per server)
- **Section 7**: Immutable audit log, field-level redaction of sensitive arguments (SHA-256 hash)

## License

Academic project — Universidad Politécnica de Madrid, 2026.
