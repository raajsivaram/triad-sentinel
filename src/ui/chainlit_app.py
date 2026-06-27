"""
Triad Sentinel — Chainlit Frontend
===================================
Visual chat interface for the multi-agent architecture triage system.
Posts user-submitted IaC / architecture text to the FastAPI backend and
renders each orchestration step (guardrails, specialist reports, sign-off)
as expandable Chainlit Steps.

Launch:
    chainlit run src/ui/chainlit_app.py
"""

import chainlit as cl
import httpx
import logging
import os
from docx import Document

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BACKEND_URL = "http://127.0.0.1:8000/triage"
REQUEST_TIMEOUT = 120.0  # seconds — LLM-backed agents can be slow

# A deliberately flawed Terraform snippet for demo purposes
SAMPLE_TERRAFORM = """\
# ---- Flawed GCP Infrastructure Blueprint ----
# This sample intentionally contains security anti-patterns for testing.

resource "google_compute_instance" "web_server" {
  name         = "prod-web-01"
  machine_type = "n2-standard-64"   # Massively over-provisioned
  zone         = "us-central1-a"    # Single-zone, no HA

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = "default"          # Using the default VPC
    access_config {}                # Assigns a PUBLIC IP directly
  }

  metadata = {
    ssh-keys = "admin:ssh-rsa AAAAB3..."   # SSH wide open
  }
}

resource "google_compute_firewall" "allow_all" {
  name    = "allow-all-ingress"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]          # All ports open to the internet
  }

  source_ranges = ["0.0.0.0/0"]    # Open to the entire world
}

resource "google_sql_database_instance" "main_db" {
  name             = "prod-sql-primary"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-n1-standard-1"       # No HA, no read replicas

    ip_configuration {
      ipv4_enabled    = true        # Public IP on the database
      authorized_networks {
        name  = "open-access"
        value = "0.0.0.0/0"         # DB accessible from anywhere
      }
    }

    backup_configuration {
      enabled = false               # Backups disabled entirely
    }
  }
}

resource "google_storage_bucket" "data_lake" {
  name     = "company-data-lake-prod"
  location = "US"

  uniform_bucket_level_access = false  # Legacy ACLs

  # No encryption key specified — defaults only
  # No lifecycle rules — unbounded cost growth
  # No versioning — no protection against accidental deletes
}
"""


# ---------------------------------------------------------------------------
# Welcome Screen
# ---------------------------------------------------------------------------
@cl.on_chat_start
async def on_chat_start():
    """Send a branded welcome message with a sample-load action button."""
    actions = [
        cl.Action(
            name="load_sample",
            label="🧪 Load Flawed Terraform Example",
            description="Insert a deliberately insecure GCP Terraform blueprint into the chat",
            payload={"action": "load_sample"},
        )
    ]

    await cl.Message(
        content=(
            "# 🛡️ Triad Sentinel\n\n"
            "Welcome to the **Triad Sentinel** multi-agent architecture triage console.\n\n"
            "Paste any **Infrastructure-as-Code template**, **cloud architecture blueprint**, "
            "or **Statement of Work** below, and the system will route it through:\n\n"
            "| Step | Agent | Purpose |\n"
            "|------|-------|---------|\n"
            "| 1 | **Ingestion Guardrail** | Scans for leaked secrets & credentials |\n"
            "| 2 | **Security Compliance Specialist** | Zero-trust, IAM, encryption audit |\n"
            "| 3 | **SRE & FinOps Specialist** | HA, scaling, cost optimisation review |\n"
            "| 4 | **Architecture Supervisor** | Executive sign-off & consolidated report |\n\n"
            "---\n"
            "> 💡 **Tip:** Click the button below to load a sample flawed Terraform file, "
            "or paste your own specification directly."
        ),
        actions=actions,
    ).send()


# ---------------------------------------------------------------------------
# Action Callback — Load Sample
# ---------------------------------------------------------------------------
@cl.action_callback("load_sample")
async def on_load_sample(action: cl.Action):
    """Inject the sample Terraform snippet and trigger the triage pipeline."""
    await action.remove()

    # Show the sample as a user-style message
    await cl.Message(
        content=f"```hcl\n{SAMPLE_TERRAFORM}\n```",
        author="user",
    ).send()

    # Run the triage flow
    await _run_triage(SAMPLE_TERRAFORM)


# ---------------------------------------------------------------------------
# Message Handler
# ---------------------------------------------------------------------------
@cl.on_message
async def on_message(message: cl.Message):
    """Handle free-form user input and send it through the triage pipeline."""
    file_content = ""
    if message.elements:
        for element in message.elements:
            file_name = element.name.lower()
            try:
                # Handle standard text/IaC/Mermaid files
                if file_name.endswith(('.mmd', '.mermaid', '.tf', '.json', '.yaml', '.yml', '.md', '.txt', '.hcl', '.sow')):
                    with open(element.path, 'r', encoding='utf-8') as f:
                        file_content += f.read() + "\n\n"
                # Handle binary Word documents
                elif file_name.endswith('.docx'):
                    doc = Document(element.path)
                    text = "\n".join([para.text for para in doc.paragraphs])
                    file_content += text + "\n\n"
                else:
                    await cl.Message(content=f"⚠️ Unsupported file type: {element.name}. Please upload text, IaC, Mermaid, or .docx files.").send()
                    return
            except Exception as e:
                await cl.Message(content=f"⚠️ Error reading file {element.name}: {str(e)}").send()
                return

        # Visual confirmation
        await cl.Message(content=f"📄 Successfully extracted content from {len(message.elements)} attached file(s).").send()

    # Combine user text with file content
    full_input = ((message.content or "") + "\n\n" + file_content).strip()
    if not full_input:
        await cl.Message(content="⚠️ Please provide text or attach a valid architecture file.").send()
        return

    await _run_triage(full_input)


# ---------------------------------------------------------------------------
# Core Triage Flow
# ---------------------------------------------------------------------------
async def _run_triage(full_input: str):
    """
    POST the architecture text to the FastAPI backend and visualise the
    response as a series of Chainlit Steps.
    """

    # ------------------------------------------------------------------
    # 1. Call the backend
    # ------------------------------------------------------------------
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.post(
                BACKEND_URL,
                json={"raw_spec": full_input},
            )
            response.raise_for_status()
    except httpx.ConnectError:
        await cl.Message(
            content=(
                "## ⚠️ Connection Error\n\n"
                "Could not reach the Triad Sentinel backend at "
                f"`{BACKEND_URL}`.\n\n"
                "Please make sure the FastAPI server is running:\n"
                "```bash\n"
                "python -m uvicorn src.main:app --port 8000\n"
                "```"
            )
        ).send()
        return
    except httpx.TimeoutException:
        await cl.Message(
            content=(
                "## ⏱️ Request Timeout\n\n"
                f"The backend did not respond within **{int(REQUEST_TIMEOUT)}s**. "
                "The multi-agent graph may still be processing.\n\n"
                "Consider increasing the timeout or checking the backend logs."
            )
        ).send()
        return
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 400:
            try:
                # Parse the standardized JSON response from FastAPI
                error_data = e.response.json()
                error_type = error_data.get("error_type", "GUARDRAIL_BLOCK")
                message = error_data.get("message", "Request blocked by security guardrail.")
                
                # Display the exact custom message based on the error type
                if error_type == "SECRET_EXPOSURE":
                    display_msg = f"🛑 **CRITICAL CONTEXT ERROR**\n\n{message}"
                elif error_type == "SCOPE_VIOLATION":
                    display_msg = f"🚫 **SCOPE RESTRICTED**\n\n{message}"
                elif error_type == "SECURITY_BLOCK":
                    display_msg = f"🚨 **SECURITY BLOCK**\n\n{message}"
                else:
                    display_msg = f"⚠️ **{error_type}**\n\n{message}"
                    
                await cl.Message(content=display_msg, author="Triad Sentinel").send()
            except Exception as parse_err:
                # Fallback if JSON parsing fails
                await cl.Message(content=f"❌ Error (400): {e.response.text}", author="Triad Sentinel").send()
            return
        
        # Handle other HTTP errors (500, etc.)
        await cl.Message(content=f"❌ Unexpected Error (HTTP {e.response.status_code})", author="Triad Sentinel").send()
        return

    # ------------------------------------------------------------------
    # 4. Parse the successful JSON response
    # ------------------------------------------------------------------
    try:
        data = response.json()
        compliance_summary = data.get("compliance_summary", "_No report returned._")
        sre_summary = data.get("sre_summary", "_No report returned._")
        executive_signoff = data.get("executive_signoff", "_No sign-off returned._")

        # ------------------------------------------------------------------
        # 5. Render Steps
        # ------------------------------------------------------------------

        # Step 1 — Ingestion Guardrail (passed if we reached here)
        async with cl.Step(name="✅ Ingestion Guardrail") as step:
            step.output = (
                "**Status:** ✅ Passed\n\n"
                "No leaked secrets, API keys, or private key material detected. "
                "Input cleared for downstream agent processing."
            )

        # Step 2 — Security Compliance Specialist
        async with cl.Step(name="🔒 Security Compliance Specialist") as step:
            step.output = (
                compliance_summary
                if compliance_summary
                else "_The Security Specialist did not return a report._"
            )

        # Step 3 — SRE & FinOps Specialist
        async with cl.Step(name="⚙️ SRE & FinOps Specialist") as step:
            step.output = (
                sre_summary
                if sre_summary
                else "_The SRE Specialist did not return a report._"
            )

        # ------------------------------------------------------------------
        # 6. Final Executive Sign-off as the main message
        # ------------------------------------------------------------------
        await cl.Message(
            content=(
                "## 📋 Executive Architecture Sign-off\n\n"
                "---\n\n"
                f"{executive_signoff}"
            )
        ).send()
    except Exception as e:
        await cl.Message(
            content=f"❌ **Unexpected Rendering Error**: {str(e)}",
            type="error"
        ).send()
        return
