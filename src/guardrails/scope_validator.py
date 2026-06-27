import re
from src.utils.logger import setup_logger

logger = setup_logger("triad_sentinel_guardrails")

# Architectural keywords that signal in-scope content
ACCEPTED_KEYWORDS = [
    "terraform", "hcl", "iac", "architecture", "blueprint", "cloud", "gcp",
    "vpc", "subnet", "iam", "encryption", "database", "compute", "kubernetes",
    "gke", "mermaid", "diagram", "sre", "reliability", "scaling", "finops",
    "cost optimization", "compliance", "stride", "security", "network",
    "load balancer", "storage", "backup", "postgres", "db", "aws", "config",
    "deploy", "api", "key", "server", "instance", "google",
    "graph td", "graph lr", "flowchart", "sequencediagram", "subgraph",
    "statement of work", "sow", "architecture document", "design doc"
]

def validate_architectural_intent(user_input: str) -> dict:
    """programmatic scope guardrail to ensure Triad Sentinel only processes cloud architecture/IaC.

    Args:
        user_input (str): The raw user input string.

    Returns:
        dict: A dictionary containing {'is_valid': bool, 'reason': str}.
    """
    logger.info(
        "Scope validation guardrail executed",
        extra={
            "component": "guardrail",
            "action": "scope_validation"
        }
    )
    if not user_input or not user_input.strip():
        logger.warning(
            "Scope validation failed: Empty input",
            extra={
                "component": "guardrail",
                "action": "scope_validation",
                "result": "blocked",
                "severity": "WARNING"
            }
        )
        return {
            "is_valid": False,
            "reason": "Out of scope: Input is empty."
        }

    input_lower = user_input.lower()

    # Check if input contains any of the accepted architectural keywords
    for keyword in ACCEPTED_KEYWORDS:
        if keyword in input_lower:
            logger.info(
                "Scope validation passed",
                extra={
                    "component": "guardrail",
                    "action": "scope_validation",
                    "result": "pass"
                }
            )
            return {
                "is_valid": True,
                "reason": "Architectural context detected."
            }

    # If no architectural context is found, block it
    logger.warning(
        "Scope validation failed: Out of scope",
        extra={
            "component": "guardrail",
            "action": "scope_validation",
            "result": "blocked",
            "severity": "WARNING"
        }
    )
    return {
        "is_valid": False,
        "reason": "Out of scope: Triad Sentinel exclusively processes cloud architecture, IaC templates, and compliance specifications."
    }
