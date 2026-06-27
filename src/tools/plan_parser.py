import json
import logging
import re
import yaml

logger = logging.getLogger(__name__)

def parse_infrastructure_plan(raw_content: str) -> str:
    """
    Parses raw Infrastructure as Code (IaC) configuration (Terraform JSON/HCL, YAML),
    Statement of Work (SOW), or architectural description strings into a structured JSON block.
    This helps downstream compliance and SRE agents systematically audit components.
    
    Args:
        raw_content (str): The raw text configuration or description.
        
    Returns:
        str: A JSON-formatted string representation of the parsed components (resources, networks, databases).

    Raises:
        None
    """
    logger.info("Parsing raw infrastructure plan/configuration.")

    # 1. Attempt JSON parsing
    try:
        data = json.loads(raw_content)
        # Wrap in standard schema
        return json.dumps({
            "format": "json",
            "parsed_data": data,
            "status": "parsed_successfully"
        }, indent=2)
    except json.JSONDecodeError:
        pass

    # 2. Attempt YAML parsing
    try:
        data = yaml.safe_load(raw_content)
        if isinstance(data, (dict, list)):
            return json.dumps({
                "format": "yaml",
                "parsed_data": data,
                "status": "parsed_successfully"
            }, indent=2)
    except Exception:
        pass

    # 3. Fallback to heuristic text parsing (e.g. SOW markdown or plain text)
    parsed = {
        "format": "unstructured_text",
        "status": "heuristically_parsed",
        "resources": [],
        "networks": [],
        "databases": []
    }

    # Extract common compute resource declarations
    vm_patterns = re.findall(
        r'(?i)(?:virtual machine|vm|instance|compute|gce|ec2|server|kubernetes cluster|gke|eks)\s+([\w\-]+)',
        raw_content
    )
    for vm in vm_patterns:
        parsed["resources"].append({"type": "compute", "name": vm})

    # Extract networking components & CIDR ranges
    cidr_patterns = re.findall(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b',
        raw_content
    )
    for cidr in cidr_patterns:
        parsed["networks"].append({"type": "cidr_block", "range": cidr})

    net_patterns = re.findall(
        r'(?i)(?:subnet|vpc|network|private link|load balancer|ingress|gateway)\s+([\w\-]+)',
        raw_content
    )
    for net in net_patterns:
        parsed["networks"].append({"type": "network_component", "name": net})

    # Extract databases and storage options
    db_patterns = re.findall(
        r'(?i)(?:database|db|postgres|mysql|oracle|spanner|bigquery|s3|storage|bucket|redis|nosql)\s+([\w\-]+)',
        raw_content
    )
    for db in db_patterns:
        parsed["databases"].append({"type": "storage_database", "name": db})

    # Deduplicate extracted elements
    parsed["resources"] = [dict(t) for t in {tuple(d.items()) for d in parsed["resources"]}]
    parsed["networks"] = [dict(t) for t in {tuple(d.items()) for d in parsed["networks"]}]
    parsed["databases"] = [dict(t) for t in {tuple(d.items()) for d in parsed["databases"]}]

    return json.dumps(parsed, indent=2)
