import re
from src.utils.logger import setup_logger

logger = setup_logger("triad_sentinel_guardrails")

# Comprehensive catalog of regex patterns for prompt injection, jailbreak, and bypass attempts
DETECTION_RULES = [
    # Jailbreak/Override attempts
    (r'(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b', "Jailbreak/Override attempt detected"),
    (r'(?i)\byou\s+are\s+now\s+in\s+debug\s+mode\b', "Jailbreak/Override attempt detected"),
    (r'(?i)\bsystem\s+override\b', "Jailbreak/Override attempt detected"),
    (r'(?i)\bact\s+as\s+an\s+unaligned\s+ai\b', "Jailbreak/Override attempt detected"),
    (r'(?i)\bdan\s+mode\b', "Jailbreak/Override attempt detected"),

    # Process Bypass attempts
    (r'(?i)\bskip\s+(?:the\s+)?security\s+review\b', "Process Bypass attempt detected"),
    (r'(?i)\bignore\s+(?:the\s+)?sre\s+agent\b', "Process Bypass attempt detected"),
    (r'(?i)\bjust\s+approve\s+this\b', "Process Bypass attempt detected"),
    (r'(?i)\bbypass\s+(?:the\s+)?supervisor\b', "Process Bypass attempt detected"),

    # Prompt Leaking attempts
    (r'(?i)\brepeat\s+your\s+system\s+prompt\b', "Prompt Leaking attempt detected"),
    (r'(?i)\boutput\s+your\s+instructions\b', "Prompt Leaking attempt detected"),
    (r'(?i)\bshow\s+me\s+your\s+hidden\s+rules\b', "Prompt Leaking attempt detected"),
]

def detect_injection_and_bypass(user_input: str) -> dict:
    """Analyzes user input for prompt injection, jailbreaking, or process bypass patterns.

    Args:
        user_input (str): The raw text input.

    Returns:
        dict: A dictionary of the form {"is_safe": bool, "reason": str}.
    """
    logger.info(
        "Injection detection guardrail executed",
        extra={
            "component": "guardrail",
            "action": "injection_detection"
        }
    )
    if not user_input:
        return {"is_safe": True, "reason": "Input is empty"}

    for pattern, description in DETECTION_RULES:
        if re.search(pattern, user_input):
            logger.warning(
                f"Injection detection failed: {description}",
                extra={
                    "component": "guardrail",
                    "action": "injection_detection",
                    "result": "blocked",
                    "severity": "WARNING"
                }
            )
            return {
                "is_safe": False,
                "reason": "Prompt Injection/Bypass detected"
            }

    logger.info(
        "Injection detection passed",
        extra={
            "component": "guardrail",
            "action": "injection_detection",
            "result": "pass"
        }
    )
    return {"is_safe": True, "reason": "Input is safe"}
