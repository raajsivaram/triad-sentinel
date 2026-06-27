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

# Exploit patterns for relaxed check on large documents
EXPLOIT_PATTERNS = [
    # Base64 encoded executable patterns or decoder executions (e.g. eval(base64.b64decode(...)))
    (r'(?i)(?:eval|exec)\(\s*(?:base64|b64decode|atob|str|bytes)\b', "Suspicious Base64 decoder execution payload"),
    # SQL Injection tautologies or UNION exploits (e.g., ' OR 1=1 --, UNION SELECT)
    (r"(?i)'\s*or\s*(?:\d+|'\w+')\s*=\s*(?:\d+|'\w+')", "SQL Injection pattern detected"),
    (r"(?i)\bunion\s+(?:all\s+)?select\b", "SQL Injection UNION query pattern detected"),
    # Cross-Site Scripting (XSS) scripts
    (r'(?i)<script\b[^>]*>.*?</script>', "XSS Script injection attempt"),
    (r'(?i)javascript\s*:\s*(?:alert|console\.log|eval|window)\b', "XSS Javascript URI pattern"),
    # Dangerous OS command injections (e.g. ; rm -rf /, | rm -rf)
    (r'(?:[;&|])\s*rm\s+-rf\b', "Dangerous OS command injection (rm -rf)"),
    (r'(?:[;&|])\s*(?:bash|sh|cmd|powershell)\s+(?:-i|-c|/c)\b', "Suspicious shell spawning command injection"),
]

def detect_injection_and_bypass(user_input: str) -> dict:
    """Analyzes user input for prompt injection, jailbreaking, or process bypass patterns.
    Supports context-aware, length-based detection zones to minimize false positives in documents.

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

    input_len = len(user_input)

    if input_len < 1000:
        # Strict Zone (Short Inputs): Apply strict patterns to the entire text
        for pattern, description in DETECTION_RULES:
            if re.search(pattern, user_input):
                logger.warning(
                    "Jailbreak attempt detected in short input header.",
                    extra={
                        "component": "guardrail",
                        "action": "injection_detection",
                        "result": "blocked",
                        "severity": "WARNING",
                        "rule": description
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

    else:
        # Relaxed Zone (Large Documents)
        header = user_input[:300]
        body = user_input[300:]

        # 1. Apply strict check to the first 300 characters (header)
        for pattern, description in DETECTION_RULES:
            if re.search(pattern, header):
                logger.warning(
                    "Jailbreak attempt detected in short input header.",  # Using warning as requested for jailbreak in header/short inputs
                    extra={
                        "component": "guardrail",
                        "action": "injection_detection",
                        "result": "blocked",
                        "severity": "WARNING",
                        "rule": description
                    }
                )
                return {
                    "is_safe": False,
                    "reason": "Prompt Injection/Bypass detected"
                }

        # 2. Apply relaxed check to the remainder of the document (body)
        for pattern, description in EXPLOIT_PATTERNS:
            if re.search(pattern, body):
                logger.warning(
                    f"Exploit payload detected in large document body: {description}",
                    extra={
                        "component": "guardrail",
                        "action": "injection_detection",
                        "result": "blocked",
                        "severity": "WARNING",
                        "rule": description
                    }
                )
                return {
                    "is_safe": False,
                    "reason": "Prompt Injection/Bypass detected"
                }

        logger.info(
            f"Large document detected ({input_len} chars). Applied relaxed security check to body, strict check to header.",
            extra={
                "component": "guardrail",
                "action": "injection_detection",
                "result": "pass"
            }
        )
        return {"is_safe": True, "reason": "Input is safe"}
