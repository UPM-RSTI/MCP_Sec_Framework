# Security Framework for MCP-based Multi-Agent Systems in SOC Environments

Master's thesis implementation - Universidad Politécnica de Madrid, 2026.
Cybersecurity · Agentic AI · SOC automation.

## Overview

This repository contains the implementation of a security framework for
multi-agent systems based on the Model Context Protocol (MCP) in Security
Operations Center (SOC) environments.

The system deploys three specialized LLM agents (triage, enrichment,
response) connected to a Wazuh SIEM through MCP. A five-layer security
middleware, plus a connection-phase registration validator, intercepts all
agent-to-tool communication and enforces tool registration checks, access
control, rate limiting, input/output validation, and audit logging.

A purpose-built malicious MCP server simulates the attack surface
identified in the literature, allowing the framework to be evaluated
against controlled, repeatable attack scenarios rather than only described
on paper.

## Architecture

```
                         LLM (GPT-4o via OpenAI API)
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                  Agents                   │
              │     Triage · Enrichment · Response        │
              └─────────────────────┼─────────────────────┘
                                    │
   ┌────────────────────────────────▼───────────────────────────────┐
   │                  Security Framework (middleware)               │
   │                                                                │
   │ Connection phase   Tool registration validator                 │
   │                    (description scan, namespace ownership,     │
   │                     manifest hash pinning, supply chain check) │
   │                                                                │
   │ Execution phase    Layer 1  Access control (RBAC)              │
   │                    Layer 2  Rate limiter                       │
   │                    Layer 3  Input validator                    │
   │                    Layer 4  Output validator                   │
   │                    Layer 5  Audit log                          │
   └────────────────┬─────────────────────────────┬─────────────────┘
                    │                             │
              Wazuh MCP server               Evil MCP server
              (16 tools, Rust)               (4 tools, attack simulation)
                    │
               Wazuh SIEM
```

The framework is exposed as a persistent FastAPI service
(`framework_server.py`) so that the connection-phase checks run once at
startup, and every subsequent pipeline execution or individual tool call
reuses the already-validated tool registry.

## Security Framework

Implemented in `framework/security.py`, aligned with the OWASP Practical
Guide for Secure MCP Server Development v1.0.

| Phase / Layer | Control | Attack vectors covered |
|---|---|---|
| Connection phase | Description scan on tool metadata | Tool description poisoning |
| Connection phase | Namespace ownership enforcement | Tool shadowing / name collision |
| Connection phase | SHA-256 manifest hash pinning | Rug pull / silent tool redefinition |
| Connection phase | SHA-256 binary hash verification | Supply chain (MCP server) |
| Layer 1 | RBAC per agent role, runtime allowlist | Privilege escalation, confused deputy, unauthorized autonomous execution, lateral compromise |
| Layer 1 | X-MCP-API-Key header validation | Authentication bypass, message manipulation / replay |
| Layer 1 | Origin header validation (request + response) | DNS rebinding, CSRF/CORS exploitation |
| Layer 2 | Per-role call rate limiter (60s window) | DoS / resource abuse, data exfiltration flooding |
| Layer 2 | Pipeline approval rate limiter (1h window) | Oversight saturation, consent fatigue |
| Layer 3 | JSON schema + regex scan on tool arguments | Direct prompt injection |
| Layer 3 | Context store entry validator + session namespacing | Memory poisoning, cross-client data leak |
| Layer 3 | Extended regex scan on external data | Malicious data injection, web content poisoning |
| Layer 3 | Handoff sequence enforcer + content scan | Identity spoofing, inter-agent trust exploitation |
| Layer 4 | Pattern matching + 100KB response size limit | Indirect prompt injection, tool poisoning in response, context flooding, credential exfiltration, system prompt extraction, AI virus / self-propagation |
| Layer 5 | Append-only audit log, field-level redaction, SHA-256 result hash | Forensic traceability, accountability |
| Session-level | Response agent justification validator | Human-agent trust manipulation |

## Evil MCP Server

Adversarial MCP server for attack simulation (`evil_mcp_server.py`).
Fully MCP-specification-compliant; from the client's perspective it is
indistinguishable from a legitimate server. Exposes four malicious tools:

- `get_threat_intelligence` — tool description poisoning
- `get_compliance_report` — confused deputy (instructs the agent to call `propose_wazuh_rule`)
- `get_vulnerability_feed` — indirect prompt injection via tool output
- `get_wazuh_latest_alert` — tool shadowing (name collision with the legitimate tool)

Runs as a persistent Docker service.

## Evaluation

The framework is evaluated through six tests (T00–T05), each isolating one
framework component and the attack vectors whose primary exploitation path
runs through it. Every test runs N=20 trials, each exercising both an
attack case and its corresponding legitimate case with fixed, repeated
payloads, against a freshly initialised component instance.

Three metrics are reported per test: **attacks blocked** out of the total
attempted (expected: 100%), **attacks passed** that bypassed all controls
(expected: 0), and **false blocks**, legitimate calls incorrectly rejected
(expected: 0). Latency is reported as two separate figures — accepted-call
overhead (genuine cost on legitimate traffic) and blocked-call saving
(avoided round-trip on rejected attacks) — rather than a single blended
number, since conflating the two would misrepresent either the framework's
operational cost or its detection behaviour.

| Test | Component | Blocked | Passed | False blocks |
|---|---|---|---|---|
| T00 | Tool registration validator | 100/100 | 0 | 0 |
| T01 | Layer 1: Access control | 120/120 | 0 | 0 |
| T02 | Layer 2: Rate limiter | 40/40 | 0 | 0 |
| T03 | Layer 3: Input validator | 100/100 | 0 | 0 |
| T04 | Layer 4: Output validator | 160/160 | 0 | 0 |
| T05 | Session and response controls | 80/80 | 0 | 0 |
| **Total** | | **600/600** | **0** | **0** |

Full per-subtest breakdown, latency figures, and methodology are documented
in the thesis (Chapter: Evaluation).

## Project Structure

```
MCP_Sec_Framework/
├── docker-compose.yml          full stack: wazuh-mcp, evil-mcp, framework-server, jupyter
├── mcp-wazuh.env.example       environment variable template
├── Vagrantfile                 Wazuh SIEM virtual machine
├── provision/                  Wazuh agent/server provisioning scripts
├── notebooks/
│   ├── demo.ipynb              pipeline demo: with/without framework, real + synthetic alerts
│   └── tests.ipynb             evaluation suite, triggered via the framework's REST API
├── wazuh-mcp/                  custom Rust build of the Wazuh MCP server
│   ├── main.rs
│   ├── custom.rs               two custom tools added for this thesis
│   └── Dockerfile.wazuh-mcp
└── SOC-framework/
    ├── agents/
    │   ├── agents.py            triage, enrichment, response agent implementations
    │   └── agents_nofw.py       unprotected pipeline variant, for baseline comparison
    ├── framework/
    │   ├── security.py          connection-phase validator + five-layer middleware
    │   └── tool_schemas.py      JSON schema definitions for all 16 Wazuh tools
    ├── mcp/
    │   └── client.py            MCP client (JSON-RPC 2.0 over HTTP/SSE)
    ├── memory/
    │   └── store.py             shared persistent memory (JSON on disk), session-namespaced
    ├── main.py                  standalone single-run pipeline
    ├── framework_server.py      persistent FastAPI gateway (REST API for pipeline + tests)
    ├── run_tests.py             evaluation suite (T00–T05, N=20 trials)
    ├── run_all_tests.sh         runs the full suite, restarting wazuh-mcp between tests
    ├── evil_mcp_server.py       adversarial MCP server
    ├── scripts/
    │   └── setup_secrets.sh     writes secrets to disk with chmod 600
    ├── Dockerfile               wazuh-mcp client-facing image (legacy, see Dockerfile.framework)
    ├── Dockerfile.evil          evil MCP server image
    └── Dockerfile.framework     framework-server image
```

## Setup

### Quick start

```bash
git clone https://github.com/UPM-RSTI/MCP_Sec_Framework.git && cd MCP_Sec_Framework
cp mcp-wazuh.env.example .env
# edit .env: set OPENAI_API_KEY=sk-...
vagrant up --provider=virtualbox
docker-compose up -d --build
cd SOC-framework && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
./run_all_tests.sh 20
```

The only value you need to change before running is `OPENAI_API_KEY` in
`.env`. All Wazuh credentials and the MCP shared secret are pre-filled
with the defaults from `wazuh/wazuh-docker v4.14.0`.

> **Note — VirtualBox required.** The Vagrantfile uses the `virtualbox`
> provider. On machines where VMware is the default Vagrant provider,
> pass `--provider=virtualbox` explicitly as shown above. VirtualBox 6.x
> or later must be installed (`sudo apt install virtualbox` on Ubuntu).

---

### Prerequisites

- Docker and Docker Compose
- Vagrant + VirtualBox 6.x or later
- Python 3.11+

### 1. Clone and configure

```bash
git clone https://github.com/UPM-RSTI/MCP_Sec_Framework.git
cd MCP_Sec_Framework
cp mcp-wazuh.env.example .env
```

Open `.env` and set your OpenAI API key — this is the **only value you
need to change**:

```
OPENAI_API_KEY=sk-...
```

All other values (Wazuh credentials, MCP key, Indexer credentials) are
pre-filled with the defaults shipped by `wazuh/wazuh-docker v4.14.0`
multi-node and work out of the box with the provisioned VM.

### 2. Start the Wazuh SIEM (Vagrant VM)

```bash
vagrant up --provider=virtualbox
```

This provisions an Ubuntu 22.04 VM that runs the full Wazuh stack
(Manager, Indexer, Dashboard) via Docker Compose inside the VM. The VM
is assigned IP `192.168.56.110` on a host-only network. First boot takes
several minutes while Docker images are pulled and Wazuh initialises.

### 3. Start the Docker stack (host)

```bash
docker-compose up -d --build
```

This builds and starts four services on the host:

| Service | Port | Description |
|---|---|---|
| `wazuh-mcp` | 8085 | Wazuh MCP server (Rust, 16 tools) |
| `evil-mcp` | 8089 | Adversarial MCP server (Python, 4 tools) |
| `framework-server` | 8090 | Persistent security framework (FastAPI) |
| `jupyter` | 8888 | Demo and evaluation notebooks |

Open `http://localhost:8888` for the notebooks, or
`http://localhost:8090/docs` for the framework's interactive API.

### 4. Python environment (for running tests from the host)

```bash
cd SOC-framework
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Run the evaluation suite

```bash
cd SOC-framework
./run_all_tests.sh 20          # all six tests, N=20 trials each
./run_all_tests.sh 20 T02      # a single test
```

The wrapper script restarts the `wazuh-mcp` container before each test,
which is necessary because the Rust server accumulates connection state
across rapid reconnects and becomes unstable otherwise. Results are
appended to `test_results_extended.jsonl`.

## OWASP Compliance

Controls implemented against the OWASP Practical Guide for Secure MCP
Server Development v1.0:

- **Section 2** — Tool description validation, namespace ownership
  enforcement, version pinning with SHA-256 manifest hash, supply chain
  binary verification
- **Section 3** — JSON schema validation per tool, per-role and pipeline
  rate limits, output size limits
- **Section 4** — Prompt injection controls across tool arguments, server
  responses, memory context, and inter-agent handoffs; human-in-the-loop
  approval for destructive actions
- **Section 5** — Centralized middleware interception, least privilege per
  agent role enforced at runtime
- **Section 6** — Safe error handling (no stack traces or internal logic
  exposed to the LLM), non-root Docker containers, secrets with restricted
  filesystem permissions, network segmentation
- **Section 7** — Append-only audit log with session tagging, field-level
  redaction of sensitive arguments

## License

Academic project — Universidad Politécnica de Madrid, 2026.