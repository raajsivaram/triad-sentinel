import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("TriadSentinelPolicyServer")

@mcp.resource("policy://zero_trust_iam.md")
def get_zero_trust_policy() -> str:
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../policies/zero_trust_iam.md'))
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

@mcp.resource("policy://ha_compute_rules.md")
def get_ha_compute_rules() -> str:
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../policies/ha_compute_rules.md'))
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

@mcp.resource("policy://finops_baselines.md")
def get_finops_baselines() -> str:
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../policies/finops_baselines.md'))
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

@mcp.tool()
def fetch_policy_baseline(policy_name: str) -> str:
    """
    Fetches the corporate security baseline policy document content by name (e.g. 'zero_trust_iam.md' or 'ha_compute_rules.md').
    """
    # Mitigate path traversal risks by using only the basename of the requested policy
    safe_name = os.path.basename(policy_name)
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../policies', safe_name))
    if not os.path.exists(path):
        raise FileNotFoundError(f"Requested baseline document not found: {policy_name}")
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

if __name__ == "__main__":
    # CRITICAL: Use stdio transport so ADK spawns it as a subprocess, avoiding HTTP/mTLS errors
    mcp.run(transport="stdio")
