import json
import logging
import re

logger = logging.getLogger(__name__)

def parse_mermaid_architecture(mermaid_code: str) -> str:
    """Parses a Mermaid flowchart/graph diagram into a structured JSON string.

    This function extracts nodes (interpreting shapes as specific cloud component types),
    connections (retaining style and traffic/protocol labels), and security zones
    (derived from subgraphs).

    Example:
        >>> diagram = '''
        ... flowchart TD
        ...     subgraph DMZ ["DMZ Zone"]
        ...         C[/API Gateway/]
        ...     end
        ...     subgraph Private [Private Subnet]
        ...         A[(Database)]
        ...         B([Cloud Service])
        ...     end
        ...     D{{User}} -->|HTTPS| C
        ...     C --> B
        ...     B -.->|SQL| A
        ... '''
        >>> print(parse_mermaid_architecture(diagram))
        {
          "format": "mermaid",
          "status": "parsed_successfully",
          "nodes": [
            {"id": "C", "label": "API Gateway", "type": "api_gateway"},
            {"id": "A", "label": "Database", "type": "database"},
            {"id": "B", "label": "Cloud Service", "type": "cloud"},
            {"id": "D", "label": "User", "type": "external_actor"}
          ],
          "connections": [
            {"source": "D", "target": "C", "style": "solid", "label": "HTTPS"},
            {"source": "C", "target": "B", "style": "solid", "label": ""},
            {"source": "B", "target": "A", "style": "dashed", "label": "SQL"}
          ],
          "security_zones": [
            {"zone": "DMZ Zone", "nodes": ["C"]},
            {"zone": "Private Subnet", "nodes": ["A", "B"]}
          ]
        }

    Args:
        mermaid_code: The raw Mermaid flowchart or graph string.

    Returns:
        str: A JSON-formatted string matching the output schema.

    Raises:
        ValueError: If the diagram has invalid Mermaid syntax (unbalanced subgraphs,
            unsupported graph types, or no parseable components).
    """
    logger.info("Starting parsing of Mermaid architecture diagram.")

    # 1. Basic validation: must declare a graph/flowchart
    if not mermaid_code or not mermaid_code.strip():
        raise ValueError("The provided Mermaid diagram is empty.")

    # Strip out Mermaid configuration directives (e.g., %%{init: ...}%%)
    cleaned_text = re.sub(r'%%\{.*?\}%%', '', mermaid_code, flags=re.DOTALL)
    # Strip out standard Mermaid comments (e.g., %% comment %%)
    cleaned_text = re.sub(r'%%.*?%%', '', cleaned_text)
    # Strip leading/trailing whitespace
    cleaned_text = cleaned_text.strip()

    if not cleaned_text:
        raise ValueError("The provided Mermaid diagram is empty.")

    if not cleaned_text.lower().startswith(('graph', 'flowchart')):
        raise ValueError("Invalid Mermaid diagram. The input must contain a 'flowchart' or 'graph' declaration.")

    # 2. Setup parsing states
    nodes = {}  # id -> {"id": id, "label": label, "type": type}
    connections = []
    security_zones = []
    active_subgraphs = []

    # Regex definitions for node shapes (ordered by specificity)
    shape_patterns = [
        ("database", r'(\b\w+)\s*\[\(\s*["\']?(.*?)["\']?\s*\)\]'),
        ("cloud", r'(\b\w+)\s*\(\[\s*["\']?(.*?)["\']?\s*\]\)'),
        ("api_gateway", r'(\b\w+)\s*\[/\s*["\']?(.*?)["\']?\s*/\]'),
        ("api_gateway", r'(\b\w+)\s*\\\\\s*["\']?(.*?)["\']?\s*\\\\'),
        ("external_actor", r'(\b\w+)\s*\{\{\s*["\']?(.*?)["\']?\s*\}\}'),
        ("standard", r'(\b\w+)\s*\[\s*["\']?(.*?)["\']?\s*\]'),
        ("standard", r'(\b\w+)\s*\(\s*["\']?(.*?)["\']?\s*\)'),
        ("standard", r'(\b\w+)\s*\(\(\s*["\']?(.*?)["\']?\s*\)\)'),
        ("standard", r'(\b\w+)\s*\{\s*["\']?(.*?)["\']?\s*\}'),
    ]

    # Regex definitions for connections (ordered by specificity)
    connection_patterns = [
        # Dashed with inline text: A -.->|label| B or A -. label .-> B
        ("dashed", r'(\b\w+)\s*-\.->\s*\|([^|]+)\|\s*(\b\w+)', 2),
        ("dashed", r'(\b\w+)\s*-\.\s*([^\.]+)\s*\.->\s*(\b\w+)', 2),
        ("dashed", r'(\b\w+)\s*-\.->\s*(\b\w+)', 0),

        # Bold/Thick with inline text: A ==>|label| B or A == label ==> B
        ("bold", r'(\b\w+)\s*==>\s*\|([^|]+)\|\s*(\b\w+)', 2),
        ("bold", r'(\b\w+)\s*==\s*([^=]+)\s*==>\s*(\b\w+)', 2),
        ("bold", r'(\b\w+)\s*==>\s*(\b\w+)', 0),

        # Solid with inline text: A -->|label| B or A -- label --> B
        ("solid", r'(\b\w+)\s*-->\s*\|([^|]+)\|\s*(\b\w+)', 2),
        ("solid", r'(\b\w+)\s*--\s*([^-]+)\s*-->\s*(\b\w+)', 2),
        ("solid", r'(\b\w+)\s*-->\s*(\b\w+)', 0),
    ]

    # Split into lines and process
    lines = cleaned_text.splitlines()
    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("%%") or re.match(r'(?i)^\s*(?:flowchart|graph)\b', line):
            # Skip empty lines, comments, or the header
            continue

        # 3. Detect subgraphs
        # subgraph ID [Label] or subgraph ID ["Label"] or subgraph ID
        subgraph_match = re.match(r'^\s*subgraph\s+(\w+)(?:\s+(.*))?$', line, re.IGNORECASE)
        if subgraph_match:
            sub_id, sub_label = subgraph_match.groups()
            if sub_label:
                sub_label = sub_label.strip()
                if sub_label.startswith('["') and sub_label.endswith('"]'):
                    sub_label = sub_label[2:-2]
                elif sub_label.startswith('[') and sub_label.endswith(']'):
                    sub_label = sub_label[1:-1]
                elif sub_label.startswith('"') and sub_label.endswith('"'):
                    sub_label = sub_label[1:-1]
                elif sub_label.startswith("'") and sub_label.endswith("'"):
                    sub_label = sub_label[1:-1]
            
            zone_name = sub_label if sub_label else sub_id
            active_subgraphs.append({"zone": zone_name, "nodes": []})
            continue

        # Detect end of subgraph
        if re.match(r'^\s*end\b', line, re.IGNORECASE):
            if not active_subgraphs:
                raise ValueError(
                    f"Syntax Error on line {line_num}: 'end' statement found with no matching 'subgraph'."
                )
            completed_subgraph = active_subgraphs.pop()
            # Only record non-empty security zones
            if completed_subgraph["nodes"]:
                security_zones.append(completed_subgraph)
            continue

        # 4. Extract node shape declarations and clean the line
        cleaned_line = line
        nodes_found_in_line = set()

        for shape_type, pattern in shape_patterns:
            matches = list(re.finditer(pattern, cleaned_line))
            for match in matches:
                node_id, label = match.groups()
                # Store or update node details
                nodes[node_id] = {
                    "id": node_id,
                    "label": label.strip(),
                    "type": shape_type
                }
                nodes_found_in_line.add(node_id)
                # Remove shape notation to simplify connection parsing, e.g. A[(Db)] -> A
                cleaned_line = cleaned_line.replace(match.group(0), node_id)

        # Assign discovered nodes to current active subgraph/security zone
        if active_subgraphs and nodes_found_in_line:
            active_subgraphs[-1]["nodes"].extend(list(nodes_found_in_line))

        # 5. Extract connections from the cleaned line
        connection_matched = False
        for style, pattern, num_groups in connection_patterns:
            match = re.search(pattern, cleaned_line)
            if match:
                connection_matched = True
                if num_groups == 2:
                    source, label, target = match.groups()
                    lbl = label.strip()
                else:
                    source, target = match.groups()
                    lbl = ""

                connections.append({
                    "source": source,
                    "target": target,
                    "style": style,
                    "label": lbl
                })

                # Ensure source and target nodes exist in our node list
                for n_id in (source, target):
                    if n_id not in nodes:
                        nodes[n_id] = {
                            "id": n_id,
                            "label": n_id,
                            "type": "standard"
                        }
                        if active_subgraphs:
                            active_subgraphs[-1]["nodes"].append(n_id)

    # Validate that all subgraphs were correctly closed
    if active_subgraphs:
        unclosed_subgraphs = ", ".join([g["zone"] for g in active_subgraphs])
        raise ValueError(
            f"Syntax Error: The following subgraphs were not closed with an 'end' statement: {unclosed_subgraphs}."
        )

    # Validate that we successfully parsed some elements of architecture
    if not nodes and not connections:
        raise ValueError(
            "Invalid Mermaid diagram. No architectural components (nodes or connections) could be parsed."
        )

    # Format the result matching the output format of plan_parser.py
    result = {
        "format": "mermaid",
        "status": "parsed_successfully",
        "nodes": list(nodes.values()),
        "connections": connections,
        "security_zones": security_zones
    }

    return json.dumps(result, indent=2)
