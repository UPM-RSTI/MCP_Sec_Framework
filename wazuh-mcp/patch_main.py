#!/usr/bin/env python3
"""
patch_main.py — injects CustomTools registration into mcp-server-wazuh main.rs.

Looks for the block where other tool modules are instantiated and adds:
  - import of custom module
  - instantiation of CustomTools
  - registration with .with_tool()
"""
import re
import sys

with open("src/main.rs", "r") as f:
    src = f.read()

# 1. Add use statement for custom module after the last tools:: use
use_patch = "use crate::tools::custom::CustomTools;"
if use_patch not in src:
    src = re.sub(
        r'(use crate::tools::vulnerabilities::\w+;)',
        r'\1\nuse crate::tools::custom::CustomTools;',
        src
    )

# 2. Add CustomTools instantiation after AlertTools (or VulnerabilityTools)
init_patch = """
    let custom_tools = CustomTools::new(
        Arc::clone(&indexer_client),
        Arc::clone(&api_client),
    );"""

if "CustomTools::new" not in src:
    # Insert after the last ToolName::new(...) block
    src = re.sub(
        r'(let alert_tools\s*=\s*AlertTools::new[^;]+;)',
        r'\1' + init_patch,
        src
    )

# 3. Register with .with_tool() — find the server builder chain
if ".with_tool(custom_tools" not in src:
    src = re.sub(
        r'(\.with_tool\(alert_tools(?:\.clone\(\))?\))',
        r'\1\n            .with_tool(custom_tools.clone())',
        src
    )

with open("src/main.rs", "w") as f:
    f.write(src)

print("patch_main.py: main.rs patched successfully")
