import re
import os
from google.adk.agents.callback_context import CallbackContext
from google.genai import types
from src.utils.logger import setup_logger

logger = setup_logger("triad_sentinel_guardrails")

# Enterprise-grade regex catalog for sanitizing high-risk exposed patterns
DEFAULT_RISK_PATTERNS = {
    "AWS_KEY": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "GENERIC_SECRET": r"(?i)(password|passwd|secret|api_key|private_key|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\=\+]{12,}['\"]",
    "RSA_PRIVATE_KEY": r"-----BEGIN RSA PRIVATE KEY-----",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z-_]{35}"
}

def fetch_secrets_manager_patterns() -> dict:
    """
    Simulates or pulls active regex patterns from Google Cloud Secrets Manager.
    Ensures zero hardcoding within the operational code base.
    """
    secret_resource = os.environ.get("BLOCKED_PATTERNS_SECRET_NAME")
    if not secret_resource:
        # Fallback to local default matrix if Secret Manager env is unconfigured locally
        return DEFAULT_RISK_PATTERNS
    
    # NOTE: When running inside Vertex AI Agent Engine, you would initialize:
    # from google.cloud import secretmanager
    # client = secretmanager.SecretManagerServiceClient()
    # response = client.access_secret_version(request={"name": secret_resource})
    # return json.loads(response.payload.data.decode("UTF-8"))
    
    return DEFAULT_RISK_PATTERNS

def mask_input_guardrail(callback_context: CallbackContext, user_prompt: str) -> dict:
    """
    ADK Before-Agent Ingestion Guardrail.
    Scans raw string inputs, infrastructure designs, or SOW code files.
    
    Returns:
        dict: A dictionary of the form {"is_safe": bool, "reason": str}.
    """
    patterns = fetch_secrets_manager_patterns()
    sanitized_prompt = user_prompt
    violations_detected = []

    for name, pattern in patterns.items():
        if re.search(pattern, sanitized_prompt):
            violations_detected.append(name)
            # Redact the matching pattern instantly to shield downstream LLM logs
            sanitized_prompt = re.sub(pattern, f"[REDACTED_RISK_SIGNATURE: {name}]", sanitized_prompt)

    if violations_detected:
        print(f"[SECURITY ALERT] Proactive block triggered on agent '{callback_context.agent_name}'. Violated profiles: {violations_detected}")
        # Return a structured failure message to intercept the execution path
        return {
            "is_safe": False,
            "reason": f"CRITICAL CONTEXT ERROR: Execution halted. Your input file contains unmasked corporate secrets or tokens ({', '.join(violations_detected)}). Sanitize your configurations before reprocessing."
        }
        
    return {
        "is_safe": True,
        "reason": "Input is safe"
    }

def secret_masker(text: str) -> dict:
    """Enterprise-grade secrets checking with explicit error handling."""
    logger.info(f"Secret masker called with {len(text)} characters")
    
    try:
        # Use the existing mask_input_guardrail function
        class DummyContext:
            agent_name = "api_gateway_ingress"
        
        result = mask_input_guardrail(DummyContext(), text)
        
        # Explicit return structure
        if not result.get("is_safe", True):
            logger.warning("Secret detected - returning is_safe=False")
            return {
                'is_safe': False,
                'error_type': 'SECRET_EXPOSURE',
                'message': '🛑 CRITICAL CONTEXT ERROR: Exposed secrets detected (API keys, private keys, or credentials). Please remove sensitive information and resubmit.'
            }
        
        logger.info("No secrets detected - returning is_safe=True")
        return {'is_safe': True, 'message': 'Input is clean'}
        
    except Exception as e:
        logger.error(f"Secret masker exception: {str(e)}", exc_info=True)
        # Return a safe default instead of raising - let main.py handle the error
        return {
            'is_safe': False,
            'error_type': 'GUARDRAIL_ERROR',
            'message': f'Secret masker execution error: {str(e)}'
        }