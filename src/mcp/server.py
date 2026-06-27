import os
import glob
from mcp.server.fastapi import FastApiServer
from mcp.types import (
    Resource,
    ReadResourceResult,
    TextResourceContents,
    Tool,
    CallToolResult,
    TextContent,
)

# Initialize the FastApiServer wrapper for Model Context Protocol
mcp_server = FastApiServer(
    name="enterprise_policy_mcp",
    version="1.0.0",
    description="Provides real-time access to corporate security baselines and SRE sizing guides."
)

POLICIES_DIR = os.environ.get("POLICIES_PATH", "./policies")

@mcp_server.list_resources()
async def list_policy_resources() -> list[Resource]:
    """
    Scans the designated policy index directory and surfaces 
    available reference materials as discoverable MCP resources.
    """
    resources = []
    search_path = os.path.join(POLICIES_DIR, "*.md")
    
    for file_path in glob.glob(search_path):
        filename = os.path.basename(file_path)
        resource_uri = f"policy://{filename}"
        
        resources.append(
            Resource(
                uri=resource_uri,
                name=f"Corporate Baseline: {filename}",
                description=f"Standard architectural rules housed within {filename}",
                mimeType="text/markdown"
            )
        )
    return resources

@mcp_server.read_resource()
async def read_policy_resource(uri: str) -> ReadResourceResult:
    """
    Reads the requested policy file from disk or local container storage 
    and returns its string contents securely to the requesting agent.
    """
    if not uri.startswith("policy://"):
        raise ValueError(f"Invalid resource schema identifier: {uri}")
        
    filename = uri.replace("policy://", "")
    # Mitigate path traversal risks by isolating the target file name
    safe_path = os.path.abspath(os.path.join(POLICIES_DIR, os.path.basename(filename)))
    
    if not os.path.exists(safe_path):
        raise FileNotFoundError(f"Requested baseline document not found: {filename}")
        
    with open(safe_path, "r", encoding="utf-8") as f:
        file_content = f.read()
        
    return ReadResourceResult(
        contents=[
            TextResourceContents(
                uri=uri,
                mimeType="text/markdown",
                text=file_content
            )
        ]
    )

@mcp_server.list_tools()
async def list_policy_tools() -> list[Tool]:
    """
    Exposes available MCP tools to query compliance baseline rules.
    """
    return [
        Tool(
            name="fetch_policy_baseline",
            description="Fetches the corporate security baseline policy document content by name (e.g. 'zero_trust_iam.md' or 'ha_compute_rules.md').",
            inputSchema={
                "type": "object",
                "properties": {
                    "policy_name": {
                        "type": "string",
                        "description": "The filename of the policy (e.g., 'zero_trust_iam.md' or 'ha_compute_rules.md')"
                    }
                },
                "required": ["policy_name"]
            }
        )
    ]

@mcp_server.call_tool()
async def call_policy_tool(name: str, arguments: dict) -> CallToolResult:
    """
    Invokes the requested policy lookup tool.
    """
    if name == "fetch_policy_baseline":
        policy_name = arguments.get("policy_name")
        if not policy_name:
            raise ValueError("Missing 'policy_name' argument")
        
        # Security Boundary: Mitigate path traversal risks by isolating the target file name
        safe_path = os.path.abspath(os.path.join(POLICIES_DIR, os.path.basename(policy_name)))
        
        if not os.path.exists(safe_path):
            raise FileNotFoundError(f"Requested baseline document not found: {policy_name}")
            
        with open(safe_path, "r", encoding="utf-8") as f:
            file_content = f.read()
            
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=file_content
                )
            ]
        )
    raise ValueError(f"Tool {name} not found")

if __name__ == "__main__":
    import uvicorn
    print(f"Starting localized MCP Policy Context Engine targeting directory: {POLICIES_DIR}")
    # Run the server on localhost port 8001 for development routing
    uvicorn.run(mcp_server.app, host="127.0.0.1", port=8001)