import json
import pytest
from src.tools.mermaid_parser import parse_mermaid_architecture

def test_parse_mermaid_architecture_valid():
    diagram = """
    flowchart TD
        subgraph DMZ ["DMZ Zone"]
            C[/API Gateway/]
        end
        subgraph Private [Private Subnet]
            A[(Database)]
            B([Cloud Service])
        end
        D{{User}} -->|HTTPS| C
        C --> B
        B -.->|SQL| A
    """
    
    result_str = parse_mermaid_architecture(diagram)
    result = json.loads(result_str)
    
    assert result["format"] == "mermaid"
    assert result["status"] == "parsed_successfully"
    
    # Check nodes
    nodes = {n["id"]: n for n in result["nodes"]}
    assert len(nodes) == 4
    assert nodes["C"]["type"] == "api_gateway"
    assert nodes["C"]["label"] == "API Gateway"
    assert nodes["A"]["type"] == "database"
    assert nodes["A"]["label"] == "Database"
    assert nodes["B"]["type"] == "cloud"
    assert nodes["B"]["label"] == "Cloud Service"
    assert nodes["D"]["type"] == "external_actor"
    assert nodes["D"]["label"] == "User"

    # Check connections
    connections = result["connections"]
    assert len(connections) == 3
    # connection D -> C
    conn_dc = next(c for c in connections if c["source"] == "D" and c["target"] == "C")
    assert conn_dc["style"] == "solid"
    assert conn_dc["label"] == "HTTPS"
    
    # connection C -> B
    conn_cb = next(c for c in connections if c["source"] == "C" and c["target"] == "B")
    assert conn_cb["style"] == "solid"
    assert conn_cb["label"] == ""
    
    # connection B -> A
    conn_ba = next(c for c in connections if c["source"] == "B" and c["target"] == "A")
    assert conn_ba["style"] == "dashed"
    assert conn_ba["label"] == "SQL"

    # Check security zones
    zones = {z["zone"]: z for z in result["security_zones"]}
    assert len(zones) == 2
    assert "C" in zones["DMZ Zone"]["nodes"]
    assert "A" in zones["Private Subnet"]["nodes"]
    assert "B" in zones["Private Subnet"]["nodes"]


def test_parse_mermaid_architecture_empty():
    with pytest.raises(ValueError, match="empty"):
        parse_mermaid_architecture("")


def test_parse_mermaid_architecture_invalid_header():
    with pytest.raises(ValueError, match="start with a 'flowchart' or 'graph'"):
        parse_mermaid_architecture("sequenceDiagram\nAlice->Bob: Hello")


def test_parse_mermaid_architecture_unclosed_subgraph():
    diagram = """
    flowchart TD
        subgraph DMZ
            A[Node]
    """
    with pytest.raises(ValueError, match="subgraphs were not closed"):
        parse_mermaid_architecture(diagram)


def test_parse_mermaid_architecture_unmatched_end():
    diagram = """
    flowchart TD
        end
    """
    with pytest.raises(ValueError, match="no matching 'subgraph'"):
        parse_mermaid_architecture(diagram)


def test_parse_mermaid_architecture_no_components():
    diagram = """
    flowchart TD
    """
    with pytest.raises(ValueError, match="No architectural components"):
        parse_mermaid_architecture(diagram)
