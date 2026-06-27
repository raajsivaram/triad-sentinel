import sys
import os
import asyncio
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
from dotenv import load_dotenv

# Load environment configuration from .env if present
load_dotenv()

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
    # Support backward compatibility for architecture_text if raw_spec is missing
    if not request.raw_spec and request.architecture_text:
        request.raw_spec = request.architecture_text

    # Check secrets FIRST
    secret_check = secret_masker(request.raw_spec or "")
    if not secret_check['is_safe']:
        raise HTTPException(
            status_code=400,
            detail={
                'error': 'SECRET_EXPOSURE',
                'message': secret_check['message']
            }
        )

    try:
        raw_spec = request.raw_spec
        if not raw_spec:
            raise HTTPException(status_code=400, detail="Missing specification text.")

        request_id = request.request_id if request.request_id else "unknown"

        logger.info(
            "Triage request received",
            extra={
                "request_id": request_id,
                "spec_length": len(raw_spec),
                "endpoint": "/triage",
                "component": "api",
                "action": "triage_request"
            }
        )
        
        # 2. Check for Scope & Intent Validation
        scope_result = validate_architectural_intent(raw_spec)
        if not scope_result["is_valid"]:
            logger.warning(
                f"Scope violation detected: {scope_result['reason']}",
                extra={
                    "request_id": request_id,
                    "component": "guardrail",
                    "action": "scope_validation",
                    "result": "blocked",
                    "severity": "WARNING"
                }
            )
            return JSONResponse(
                status_code=400,
                content={"error": "SCOPE_VIOLATION", "message": scope_result["reason"]}
            )
            
        # 3. Check for Prompt Injection / Jailbreaks / Process Bypass
        injection_result = detect_injection_and_bypass(raw_spec)
        if not injection_result["is_safe"]:
            logger.warning(
                "Prompt injection/process bypass detected",
                extra={
                    "request_id": request_id,
                    "component": "guardrail",
                    "action": "injection_detection",
                    "result": "blocked",
                    "severity": "WARNING"
                }
            )
            return JSONResponse(
                status_code=400,
                content={"error": "SECURITY_BLOCK", "message": "Malicious intent or process bypass detected."}
            )
            
        # 4. Instantiate and trigger our compiled ADK Graph Workflow using a context-managed Runner
        triage_graph = build_triage_workflow()
        
        from google.adk.runners import InMemoryRunner
        from google.genai import types
        
        state_delta = {
            "raw_input": raw_spec,
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
                final_state = session.state.to_dict() if session else {}
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
            f"Unexpected error in /triage: {str(e)}",
            exc_info=True,
            extra={
                "component": "api",
                "action": "triage_request",
                "result": "fail",
                "severity": "ERROR"
            }
        )
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


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