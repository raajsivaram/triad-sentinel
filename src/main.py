import sys
import os
import asyncio
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from src.utils.logger import setup_logger

logger = setup_logger("triad_sentinel_api")

# Prevent local 'src/mcp' folder from shadowing global 'mcp' dependency by removing 'src' from sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir in sys.path:
    sys.path.remove(script_dir)

# Add project root to sys.path to allow 'src.*' imports
project_root = os.path.abspath(os.path.join(script_dir, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from google.adk.cli.fast_api import get_fast_api_app
from google.genai import errors as genai_errors

# Import components
from src.guardrails.secret_masker import mask_input_guardrail, secret_masker
from src.guardrails.injection_detector import detect_injection_and_bypass
from src.guardrails.scope_validator import validate_architectural_intent
from src.agents.supervisor import build_triage_workflow, TriageState

# Initialize a standard FastAPI instance
app = FastAPI(
    title="Triad Sentinel",
    description="Triad Sentinel - Vertex AI Agent Engine compatible endpoint executing parallel multi-agent graph evaluations."
)

class ArchitectureRequest(BaseModel):
    raw_spec: str = None
    architecture_text: str = None
    request_id: str = "unknown"

@app.post("/triage")
async def triage_architecture(request: ArchitectureRequest):
    request_id = request.request_id if request.request_id else "unknown"
    
    # Support backward compatibility for architecture_text if raw_spec is missing
    if not request.raw_spec and request.architecture_text:
        request.raw_spec = request.architecture_text
    
    logger.info(
        "Triage request received",
        extra={
            "request_id": request_id,
            "spec_length": len(request.raw_spec or ""),
            "endpoint": "/triage",
            "component": "api",
            "action": "triage_request"
        }
    )
    
    # GUARDRAIL 1: Secret Masker (MUST BE FIRST)
    try:
        logger.info("Executing secret masker guardrail...", extra={"request_id": request_id})
        secret_check = secret_masker(request.raw_spec or "")
        logger.info(f"Secret masker result: {secret_check}", extra={"request_id": request_id})
        
        # Explicit check with detailed logging
        if not secret_check.get('is_safe', True):
            logger.warning(
                "Guardrail blocked request",
                extra={
                    "request_id": request_id,
                    "component": "guardrail",
                    "action": "secret_detection",
                    "result": "blocked",
                    "http_status": 400,
                    "error_type": "SECRET_EXPOSURE"
                }
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error_type": "SECRET_EXPOSURE",
                    "message": "🛑 CRITICAL CONTEXT ERROR: Exposed secrets detected (API keys, private keys, or credentials). Please remove sensitive information and resubmit."
                }
            )
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.error(
            f"Secret masker guardrail threw exception: {str(e)}",
            exc_info=True,
            extra={
                "request_id": request_id,
                "component": "guardrail",
                "action": "secret_detection",
                "result": "error",
                "severity": "ERROR"
            }
        )
        raise HTTPException(
            status_code=500,
            detail=f"Guardrail execution error: {str(e)}"
        )
    
    # GUARDRAIL 2: Scope & Intent Validation
    try:
        scope_result = validate_architectural_intent(request.raw_spec or "")
        if not scope_result.get("is_valid", True):
            logger.warning(
                "Guardrail blocked request",
                extra={
                    "request_id": request_id,
                    "component": "guardrail",
                    "action": "scope_validation",
                    "result": "blocked",
                    "http_status": 400,
                    "error_type": "SCOPE_VIOLATION"
                }
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error_type": "SCOPE_VIOLATION",
                    "message": "🚫 Scope restricted: I am designed exclusively for cloud architecture auditing. Please provide an IaC template, Mermaid diagram, or architectural specification."
                }
            )
    except Exception as e:
        logger.error(f"Scope validator error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scope validation error: {str(e)}")
    
    # GUARDRAIL 3: Injection Detection
    try:
        injection_result = detect_injection_and_bypass(request.raw_spec or "")
        if not injection_result.get("is_safe", True):
            logger.warning(
                "Guardrail blocked request",
                extra={
                    "request_id": request_id,
                    "component": "guardrail",
                    "action": "injection_detection",
                    "result": "blocked",
                    "http_status": 400,
                    "error_type": "SECURITY_BLOCK"
                }
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error_type": "SECURITY_BLOCK",
                    "message": "🚨 SECURITY_BLOCK: Prompt Injection/Bypass detected. Malicious intent or process bypass denied."
                }
            )
    except Exception as e:
        logger.error(f"Injection detector error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Injection detection error: {str(e)}")
    
    # ALL GUARDRAILS PASSED - Proceed to Agent Workflow
    try:
        triage_graph = build_triage_workflow()
        
        from google.adk.runners import InMemoryRunner
        from google.genai import types
        
        state_delta = {
            "raw_input": request.raw_spec,
            "compliance_report": "",
            "sre_report": "",
            "final_signoff": ""
        }
        
        new_message = types.Content(
            role="user",
            parts=[types.Part.from_text(text="Audit Architecture Proposal")]
        )
        
        logger.info(
            "[Ingress] Triggering Agent Workflow Graph Execution...",
            extra={
                "request_id": request_id,
                "component": "api",
                "action": "workflow_execution"
            }
        )
        try:
            async with InMemoryRunner(node=triage_graph) as runner:
                runner.auto_create_session = True
                async for _ in runner.run_async(
                    user_id="triad_sentinel_user",
                    session_id="session_123",
                    new_message=new_message,
                    state_delta=state_delta
                ):
                    pass
                
                session = await runner.session_service.get_session(
                    app_name=runner.app_name,
                    user_id="triad_sentinel_user",
                    session_id="session_123"
                )
                final_state = session.state if isinstance(session.state, dict) else (session.state.to_dict() if hasattr(session.state, 'to_dict') else {})
        except genai_errors.ClientError as e:
            error_msg = str(e)
            logger.error(f"Google GenAI Client Error: {error_msg}", exc_info=True)
            
            # Catch validation errors or authentication failures for both API keys and ADC
            if any(term in error_msg for term in ["API key not valid", "API_KEY_INVALID", "invalid credentials", "PERMISSION_DENIED"]):
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": "LLM_PROVIDER_ERROR",
                        "message": "🔑 LLM Authentication Error: The LLM credentials (Google API Key or Application Default Credentials) are missing, invalid, or do not have the required permissions. Please ensure your authentication settings are correctly configured."
                    }
                )
            return JSONResponse(
                status_code=500,
                content={
                    "error": "LLM_PROVIDER_ERROR",
                    "message": f"🤖 LLM Provider Error: {error_msg}"
                }
            )
        except ValueError as e:
            logger.error(
                f"Plan-Phase Security Violation: {str(e)}",
                extra={
                    "request_id": request_id,
                    "component": "api",
                    "action": "workflow_execution",
                    "result": "blocked",
                    "severity": "ERROR"
                }
            )
            raise HTTPException(status_code=400, detail=f"Plan-Phase Security Violation: {str(e)}")
        
        logger.info(
            "Triage request successfully processed",
            extra={
                "request_id": request_id,
                "component": "api",
                "action": "triage_response",
                "result": "pass"
            }
        )
        return {
            "status": "success",
            "compliance_summary": final_state.get("compliance_report", ""),
            "sre_summary": final_state.get("sre_report", ""),
            "executive_signoff": final_state.get("final_signoff", "")
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Unexpected error in workflow execution: {str(e)}",
            exc_info=True,
            extra={
                "request_id": request_id,
                "component": "api",
                "action": "workflow_execution",
                "result": "error"
            }
        )
        raise HTTPException(status_code=500, detail=f"Workflow execution error: {str(e)}")


# Vertex AI Agent Engine Native Native Hook Wrapper
# This exposes the standard app instances dynamically when packaged 
# for the cloud runtime platform environment
backend_agent_engine_app = get_fast_api_app(
    agents_dir=os.path.dirname(os.path.abspath(__file__)),
    web=False
)
backend_agent_engine_app.include_router(app.router)

if __name__ == "__main__":
    import uvicorn
    print("Launching Local Triad Sentinel Platform Gateway Server on http://127.0.0.1:8000")
    uvicorn.run("src.main:app", host="127.0.0.1", port=8000, reload=True)