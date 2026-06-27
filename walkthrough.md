# Walkthrough: Chainlit Frontend & Mermaid Parser for Triad Sentinel

## Summary

Built a Chainlit chat UI to visualise the multi-agent architecture triage pipeline, and added support for parsing Mermaid flowchart/graph architecture diagrams as a structured input format for the Triad Sentinel agent system.

---

## Files Created

### [chainlit_app.py](file:///d:/Coding_Workspace/triad-sentinel/src/ui/chainlit_app.py)
The main Chainlit application with three handlers:

| Handler | Purpose |
|---------|---------|
| `@cl.on_chat_start` | Sends a branded welcome message with an agent pipeline table and a "Load Flawed Terraform Example" action button |
| `@cl.action_callback("load_sample")` | Injects a deliberately insecure GCP Terraform snippet and triggers the triage flow |
| `@cl.on_message` | Accepts free-form architecture text and sends it through `_run_triage()` |

The core `_run_triage()` function:
1. POSTs to `http://127.0.0.1:8000/triage` via `httpx.AsyncClient` (120s timeout)
2. On **success**: renders three `cl.Step` elements (Ingestion Guardrail ✅, Security Specialist, SRE Specialist) and the Executive Sign-off as the main message
3. On **HTTP 400**: distinguishes between secret-leak blocks and plan-phase security violations
4. On **connection/timeout errors**: shows a friendly diagnostic message

### [config.toml](file:///d:/Coding_Workspace/triad-sentinel/.chainlit/config.toml)
Chainlit configuration:
- `name` → "Triad Sentinel"
- `default_theme` → "dark"
- `description` → project description for HTML meta tags

### [mermaid_parser.py](file:///d:/Coding_Workspace/triad-sentinel/src/tools/mermaid_parser.py)
A lightweight regex-based parser that:
- Extracts nodes from shapes (Hexagons `{{}}` → `external_actor`, Cylinders `[()]` → `database`, Stadiums `([])` → `cloud`, Parallelograms `[/ /]` → `api_gateway`, boxes/circles/etc. → `standard`).
- Identifies connection routing and style (`-->` → `solid`, `-.->` → `dashed`, `==>` → `bold`), mapping inline or end-of-line data-flow/protocol labels.
- Collects security zones defined via nested or flat subgraphs (DMZ, Private Subnet, Public Zone, etc.) and correctly strips formatting bracket characters.
- Detects invalid Mermaid formats (e.g. unclosed subgraphs or mismatched `end` tags) and raises informative `ValueError` exceptions.

### [test_mermaid_parser.py](file:///d:/Coding_Workspace/triad-sentinel/tests/test_mermaid_parser.py)
Tests all functionality of the parser:
- Standard valid diagrams mapping nodes, connections, and security zones
- Error conditions (empty inputs, unsupported sequence diagrams, unclosed subgraphs, unmatched `end` statements, and empty flowchart structures)

---

## Files Modified

### [requirements.txt](file:///d:/Coding_Workspace/triad-sentinel/requirements.txt)
Added two new dependencies:
- `chainlit>=2.0.0`
- `httpx>=0.27.0`

### [supervisor.py](file:///d:/Coding_Workspace/triad-sentinel/src/agents/supervisor.py)
- Imported the new `parse_mermaid_architecture` tool.
- Registered it in the `tools` list for the `architecture_supervisor` agent during graph orchestration.

---

## Verification

| Check | Result |
|-------|--------|
| Python syntax validation | ✅ Passed |
| Existing and new test suites (`pytest`) | ✅ 20/20 passed |

---

## How to Run

```bash
# Terminal 1 — Start the FastAPI backend
.\.venv\Scripts\python.exe -m uvicorn src.main:app --port 8000

# Terminal 2 — Start the Chainlit UI on port 8080
.\.venv\Scripts\chainlit run src/ui/chainlit_app.py --port 8080
```

Then open `http://localhost:8080` in your browser.
