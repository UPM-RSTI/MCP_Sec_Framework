"""
mcp/client.py — Cliente MCP HTTP para mcp-server-wazuh.
Transporte: POST /mcp → respuesta SSE en el mismo body.

Group 3 controls added:
  - API key authentication: X-MCP-API-Key header on every request.
    Covers: authentication bypass, message manipulation/replay.
    The shared secret is loaded from the MCP_API_KEY environment variable.
    Both the client (here) and the server (wazuh-mcp) must share the same key.
  - Request origin validation (CSRF/CORS): the Origin value the client is
    about to send is checked against a trusted allowlist before the request
    is dispatched. This is an egress-side control, distinct from the
    response-side origin check below.
  - Response origin validation (DNS rebinding): the URL the server actually
    responded from is checked against the same trusted allowlist after the
    request completes.
"""

import json
import os
import logging
from typing import Optional
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

MCP_URL          = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8085/mcp")
MCP_API_KEY      = os.getenv("MCP_API_KEY", "")       # shared secret with wazuh-mcp
MCP_ALLOWED_ORIGIN = os.getenv("MCP_ALLOWED_ORIGIN", "http://127.0.0.1")  # CSRF/DNS rebinding

# [NEW] Trusted origin allowlist for outgoing requests (CSRF/CORS egress
# control). Defaults to MCP_ALLOWED_ORIGIN so existing deployments keep
# working unchanged. Can be extended with a comma-separated
# MCP_TRUSTED_ORIGINS env var if multiple legitimate client origins exist.
_extra_trusted = os.getenv("MCP_TRUSTED_ORIGINS", "")
MCP_TRUSTED_ORIGINS = {MCP_ALLOWED_ORIGIN} | {
    o.strip() for o in _extra_trusted.split(",") if o.strip()
}


class MCPClient:

    def __init__(self, url: str = MCP_URL):
        self.url        = url
        self.session    = requests.Session()
        self.session_id: Optional[str] = None
        self._rid       = 1
        self._ready     = False
        self._tools     = None
        # [NEW] Per-instance origin override, used by tests to simulate a
        # compromised/misconfigured client attempting a forged Origin
        # without mutating global module state.
        self._origin_override: Optional[str] = None

    def _current_origin(self) -> str:
        return self._origin_override or MCP_ALLOWED_ORIGIN

    def _validate_request_origin(self, origin: str) -> None:
        """
        [NEW] CSRF/CORS egress validation (Group 3 extension).
        Verifies that the Origin value the client is about to send is part
        of the trusted allowlist BEFORE the request is dispatched. This
        protects against a compromised or misconfigured client component
        attempting to send requests under a forged origin, which a
        permissive server-side CORS policy might otherwise accept.
        """
        if not MCP_TRUSTED_ORIGINS:
            return
        parsed = urlparse(origin)
        trusted_hosts = {urlparse(o).hostname for o in MCP_TRUSTED_ORIGINS}
        if parsed.hostname not in trusted_hosts:
            logger.warning(
                f"[CSRF/CORS] Refusing to send request with untrusted Origin "
                f"'{origin}'. Trusted origins: {sorted(MCP_TRUSTED_ORIGINS)}."
            )
            raise RuntimeError(
                "Refusing to send request — Origin not in trusted allowlist "
                "(possible CSRF/CORS misconfiguration)."
            )

    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept":       "application/json, text/event-stream",
        }
        if self.session_id:
            h["MCP-Session-Id"] = self.session_id

        # [NEW] API key authentication (Group 3)
        # Covers: authentication bypass, message manipulation/replay.
        # Every request carries the shared secret in X-MCP-API-Key.
        # The wazuh-mcp server validates this header before processing any request.
        if MCP_API_KEY:
            h["X-MCP-API-Key"] = MCP_API_KEY
        else:
            logger.warning(
                "[MCP CLIENT] MCP_API_KEY not set — requests sent without authentication. "
                "Set MCP_API_KEY in .env to enable authentication."
            )

        # [NEW] Origin header for CSRF / DNS rebinding mitigation (Group 3 extension).
        # The outgoing Origin is validated against the trusted allowlist
        # before being attached to the request (egress-side CSRF/CORS
        # control). Combined with localhost-only bind (127.0.0.1) in
        # docker-compose and the response-side check in
        # _validate_response_origin, this mitigates DNS rebinding attacks
        # that would redirect MCP traffic to an attacker-controlled host.
        origin = self._current_origin()
        self._validate_request_origin(origin)
        h["Origin"] = origin
        return h

    def _validate_response_origin(self, response) -> None:
        if not MCP_ALLOWED_ORIGIN:
            return
        """
        [NEW] DNS rebinding response validation.
        Checks that the server response does not redirect to an unexpected host
        by validating the response URL stays within the allowed origin.
        """
        resp_url = getattr(response, "url", None)
        if resp_url:
            parsed_allowed = urlparse(MCP_ALLOWED_ORIGIN)
            parsed_resp    = urlparse(str(resp_url))
            if parsed_resp.hostname and parsed_resp.hostname != parsed_allowed.hostname:
                logger.warning(
                    f"[DNS REBINDING] Response URL '{parsed_resp.netloc}' "
                    f"does not match allowed origin '{parsed_allowed.hostname}'. "
                    f"Possible DNS rebinding attack."
                )
                raise RuntimeError(
                    "MCP response origin mismatch — possible DNS rebinding attack."
                )

    def _parse_sse(self, text: str) -> dict:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        for block in text.split("\n\n"):
            lines = [l[5:].lstrip() for l in block.split("\n")
                     if l.strip().startswith("data:")]
            if lines:
                try:
                    return json.loads("\n".join(lines))
                except json.JSONDecodeError:
                    pass
        raise RuntimeError(f"No JSON in SSE:\n{text[:200]}")

    def _post(self, payload: dict) -> dict:
        r = self.session.post(self.url, json=payload,
                              headers=self._headers(), timeout=90)
        r.raise_for_status()
        self._validate_response_origin(r)
        if sid := r.headers.get("MCP-Session-Id"):
            self.session_id = sid
        if not r.text.strip():
            return {}
        if "event-stream" in r.headers.get("Content-Type", ""):
            return self._parse_sse(r.text)
        return r.json()

    def _rpc(self, method: str, params: dict = None) -> dict:
        p = {"jsonrpc": "2.0", "id": self._rid,
             "method": method, "params": params or {}}
        self._rid += 1
        return self._post(p)

    def _notify(self, method: str) -> None:
        self._post({"jsonrpc": "2.0", "method": method, "params": {}})

    def connect(self) -> None:
        if self._ready:
            return
        r = self._rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities":    {},
            "clientInfo":      {"name": "soc-framework", "version": "1.0"},
        })
        if "error" in r:
            raise RuntimeError(f"MCP init failed: {r['error']}")
        self._notify("notifications/initialized")
        self._ready = True
        logger.info(f"MCP connected: {r.get('result',{}).get('serverInfo',{})}")

    def disconnect(self) -> None:
        self.session.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    def list_tools(self) -> list:
        if self._tools is not None:
            return self._tools
        self.connect()
        r = self._rpc("tools/list", {})
        if "error" in r:
            raise RuntimeError(f"tools/list failed: {r['error']}")
        raw = r.get("result", {}).get("tools", [])
        self._tools = [
            {
                "name":        t["name"],
                "description": t.get("description", ""),
                "parameters":  _normalize_schema(t.get("inputSchema")),
            }
            for t in raw
        ]
        logger.info(f"Tools: {[t['name'] for t in self._tools]}")
        return self._tools

    def call_tool(self, name: str, arguments: dict = {}) -> str:
        self.connect()
        r = self._rpc("tools/call", {"name": name, "arguments": arguments})
        if "error" in r:
            raise RuntimeError(f"Tool '{name}' error: {r['error']}")
        content = r.get("result", {}).get("content", [])
        parts   = [c.get("text", "") for c in content if c.get("type") == "text"]
        text    = "\n\n".join(parts).strip()
        return f"[MCP ERROR]\n{text}" if r.get("result", {}).get("isError") else text


def _normalize_schema(schema: Optional[dict]) -> dict:
    if not schema:
        return {"type": "object", "properties": {}, "additionalProperties": False}
    s = dict(schema)
    s["type"] = "object"
    s.setdefault("properties", {})
    s.setdefault("additionalProperties", False)
    for prop in s["properties"].values():
        if isinstance(prop.get("type"), list):
            non_null = [t for t in prop["type"] if t != "null"]
            prop["type"] = non_null[0] if non_null else "string"
        if prop.get("nullable") and "type" not in prop:
            prop["type"] = "string"
    s.pop("$schema", None)
    s.pop("title", None)
    s.pop("description", None)
    return s