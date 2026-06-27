# 🛡️ Triad Sentinel: Enterprise AI Architecture Review Board for Google Cloud Platform (GCP)

## 1. The Problem & Business Value
Enterprise cloud environments are highly complex and continuously evolving, exposing organizations to catastrophic security leaks and financial waste. Today, cloud architects and security engineers spend up to **40% of their valuable engineering hours** manually reviewing Infrastructure-as-Code (IaC) templates, Mermaid flowchart designs, and complex Statement of Work (SOW) documents for security compliance, site reliability engineering (SRE) failures, and FinOps anomalies. 

This manual gatekeeping creates a massive operational bottleneck, increases time-to-market, and remains highly prone to human oversight. A single misplaced configuration wildcard or unencrypted database bucket can lead to multi-million dollar data breaches or runaway operational costs.

**Triad Sentinel** is designed to solve this exact problem. Functioning as an automated, AI-powered **Architecture Review Board (ARB)** specifically optimized for the Google Cloud Platform (GCP), Triad Sentinel intercepts designs at the ingestion stage and subjects them to a rigorous multi-agent validation loop. By translating unstructured specifications, visual diagrams, and declarative configurations into structured components, Triad Sentinel evaluates them against strict, dynamic corporate policy baselines. This provides instantaneous feedback, slashing engineering review cycles from days to seconds while maintaining enterprise-grade safety.

---

## 2. The 'Vibe Coding' Journey with Antigravity
Building a production-ready, secure multi-agent system from scratch is historically a slow, syntax-heavy endeavor. However, utilizing **Antigravity** as our AI pair programmer enabled a paradigm shift into **"Vibe Coding"**—where high-level design intents and system-level boundaries were rapidly translated into functional Python components.

Antigravity acted as an accelerator across the entire lifecycle:
* **Chainlit UI Scaffolding:** Antigravity bootstrapped our frontend application, setting up real-time rendering step components (Ingestion Guardrail, Compliance Specialist, SRE Specialist, and Executive Sign-off) that dynamically update as the ADK graph runs.
* **GCP-Native FinOps & Policies:** It helped construct our grounding policy files (`zero_trust_iam.md`, `ha_compute_rules.md`, and `finops_baselines.md`), matching real-world GCP-native compliance metrics and cost reduction rules.
* **Programmatic Python Guardrails:** We co-developed four strict programmatic guardrails (Secret Masker, Scope & Intent Validator, LLM Injection Detector, and local Plan-Phase Security Gate) to safeguard LLM contexts and ensure API security.
* **AST and Regex Parsers:** Writing robust parsers is traditionally a debugging minefield. Antigravity generated the complex regex-based mapping logic inside the **Mermaid Parser**—correctly identifying shape styles (like cylinders to databases and hexagons to actors), connection styles, and security zones—and the **Plan Parser** for extracting component declarations from unstructured text or structured IaC files.

Through rapid iterative loops, Antigravity verified code syntax, added robust logging, resolved path traversal exceptions, and generated our `pytest` verification suite, allowing us to focus on the high-level security architecture of the system.

---

## 3. Architecture & Multi-Agent Design
Triad Sentinel utilizes a stateful, parallel multi-agent graph architecture built on the **Google Agent Development Kit (ADK)** and targeted for deployment on the **Vertex AI Agent Engine**. Decoupling and parallel execution ensure that each specialist agent can process input concurrently, maximizing scalability and efficiency.

The workflow is structured as follows:
* **FastAPI Ingress & Guardrails:** Incoming requests are routed through FastAPI, passing through the strict programmatic Python guardrails before the ADK graph is ever instantiated.
* **Senior Enterprise Architecture Supervisor (`architecture_supervisor`):** The graph entry point. It manages state using `TriageState`, routes components to the appropriate specialists, and compiles the final executive report. It leverages the **STRIDE Analyzer** tool to perform comprehensive threat modeling across 11 architectural component types (including Compute, Kubernetes, Serverless, CDN, VPC networking, and CI/CD pipelines).
* **Domain Specialists:** Parallel nodes invoke the **Security Compliance Specialist** and the **SRE & FinOps Specialist** in parallel.
  * The **Security Compliance Specialist** audits identity controls, public endpoints, and encryption.
  * The **SRE & FinOps Specialist** reviews high availability, scalability risks, and right-sizing parameters.
* **Model Context Protocol (MCP) Grounding:** To eliminate LLM hallucinations, the specialist agents do not rely on static system instructions. Instead, they dynamically query a local MCP Server via `stdio` transport. Using a `policy://` resource URI scheme, the specialists fetch and ground their audits using the official policy markdown documents in `/policies`:
  * `zero_trust_iam.md` (IAM limits, KMS key requirements)
  * `ha_compute_rules.md` (multi-zone configurations, MIGs)
  * `finops_baselines.md` (Spot VM mandates, lifecycle policies)
* **Consensus & Sign-off:** The Supervisor aggregates the unaltered assessments into a single executive dashboard containing a **Final Approval Gate** (`APPROVED` or `HELD_FOR_REMEDIATION`) and a consolidated list of **Mandatory Action Items** before returning the final report to the Chainlit frontend.

---

## 4. Defense-in-Depth Security
Unlike naive wrapper applications, Triad Sentinel is hardened against production exploits, prompt injection, and excessive compute spend through a four-tiered programmatic defense-in-depth model:

1. **Pre-Run Secret Interception (Secret Masker):** Operating at the FastAPI API ingress level, the Secret Masker uses regex patterns to scan for unmasked AWS keys, Google API keys, GCP Service Account JSON keys, and RSA private keys. If a secret is exposed, the request is immediately dropped before triggering the LLM, protecting corporate API credentials from leaking into LLM context logs or Cloud Logging.
2. **Domain Locking (Scope & Intent Validator):** This heuristic check filters out casual conversation, off-topic requests, and compute-draining queries (e.g., "What is the weather in London?") at the API gateway level. The validator matches inputs against allowed architectural keywords (`terraform`, `mermaid`, `sow`, etc.) and raises a `SCOPE_VIOLATION` block, protecting resource budgets.
3. **Jailbreak & Bypass Prevention (Injection Detector):** Protects the workflow against direct prompt injections, jailbreaking attempts ("ignore previous instructions"), and process bypassing attempts ("skip security review"). It employs context-aware, length-based checks: short inputs are scanned strictly, while large documents (e.g., 15k-character `.docx` SOW uploads) apply strict checks only on the first 300 characters (header/intent). The remainder of the document body is scanned using relaxed rules that ignore harmless security terminology but block malicious code injection payloads (such as SQLi, XSS, and command injections like `; rm -rf /`).
4. **Local Security Gate (Plan-Phase Gate):** Operating inside the ADK graph hook before calling downstream specialist models, this gate parses candidate file references and configurations. It blocks unauthorized directory traversals outside the local workspace root and rejects disallowed formats (like `.xml` or `.ini`), enforcing strict security boundaries.

---

## 5. Video Demo Script / Walkthrough
Our 5-minute project video demonstrates the live execution of Triad Sentinel in action.

* **0:00 - 1:00: Interface Overview & Guardrails.**
  The walkthrough begins in the Chainlit UI. We present the system greeting and the multi-agent table. We type a simple casual chat query ("Can you tell me a joke?") and click send. The Scope Validator instantly catches it and returns a clean, red-styled `SCOPE_VIOLATION` block at the API layer. We then show a payload containing an exposed AWS key: the Secret Masker triggers immediately, returning a `SECRET_EXPOSURE` block and dropping execution.
* **1:00 - 2:30: Injection Protection on Large Files.**
  We show how the Injection Detector handles a large 15,000-character SOW document. The document has security terminology in its body (discussing "Prompt Injection" defenses). It clears the relaxed body check and processes successfully. We then modify the document to prepend a jailbreak phrase ("ignore previous instructions") at the start. The strict header check catches the exploit and outputs a `SECURITY_BLOCK` error.
* **2:30 - 4:00: Mermaid & Plan Parsing.**
  We demonstrate uploading a visual architecture by attaching a flawed `.mmd` (Mermaid) file containing nested subgraphs representing a DMZ, Private Subnet, and databases. The Mermaid Parser extracts these nodes, connection styles, and security zones into a structured JSON payload. We then run the triage pipeline. The UI renders the parallel collapsible steps in real-time as the agents query the MCP policy resources.
* **4:00 - 5:00: Final Report & Remediation.**
  We review the final synthesized executive sign-off report. The supervisor merges the Compliance report (highlighting a wildcard IAM policy and lack of KMS keys) with the SRE report (highlighting GCE over-provisioning and missing versioning on buckets). The final gate is marked `HELD_FOR_REMEDIATION` with a prioritized action list, providing the developer with exact Terraform snippets to resolve the vulnerabilities.

---

## 6. Future Roadmap
The roadmap for Triad Sentinel expands its scope into a self-healing, multi-cloud automated governance solution:
* **Auto-Remediation (Self-Healing IaC):** Transitioning from listing action items to generating the actual corrected Terraform patch files (using Git pull requests) so developers can approve and merge fixes with a single click.
* **Continuous Feedback Loops:** Integrating with production Google Cloud Logging and Cloud Security Command Center to analyze post-deployment compliance drift, feeding runtime configuration violations back to the agentic training loop.
* **Multi-Cloud Policy Expansion:** Extending the MCP Server policy repository to query AWS (Well-Architected Framework) and Azure (Cloud Adoption Framework) baselines, enabling unified multi-cloud architectural auditing.
