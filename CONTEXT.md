# Triad Sentinel - Secure Coding Standards

This document establishes the project-level secure coding standards for the Triad Sentinel platform. All developer additions, agent designs, and system modifications must strictly conform to these three pillars.

---

## 1. Architectural Standards

**Multi-Agent Graph Orchestration loops must remain decoupled, stateful, and run asynchronously.**

- **Asynchronous Execution:** All node traversals, specialist analysis calls, and supervisor aggregations must be run asynchronously using native Python `async/await` syntax.
- **Stateful Workflows:** System state must be explicitly tracked using a subclass of `google.adk.workflows.WorkflowState`. Do not pass untracked, mutable global structures between graph nodes.
- **Decoupled Nodes:** Multi-agent coordination must be orchestrated using `google.adk.workflows.Graph`. Individual specialists must execute their tasks independently of other specialist nodes, allowing parallel execution.
- **Framework Uniformity:** Always use the `google-adk` framework for agent instantiation and workflow coordination.

---

## 2. Security Boundaries

**Absolute ban on hardcoded credentials, corporate keys, or plaintext secrets.**

- **Zero Hardcoding:** No plaintext secrets, tokens, API keys, or private keys may exist in source files, config files, or prompts.
- **Environment Vectors & Secret Manager Lookups:** All API connectivity and configuration parameters must be loaded dynamically from environment variables (e.g. via `os.environ` or `.env` configurations) or retrieved through lookups simulating a Google Cloud Secret Manager service wrapper.
- **Ingestion Guardrails:** Active guardrail handlers (e.g., input pattern maskers) must run before graph ingestion to intercept raw inputs and redact corporate signatures immediately, preventing logs or downstream LLM context windows from receiving plaintext secrets.

---

## 3. Anti-Hallucination Mandate

**Agents are strictly forbidden from hardcoding static compliance guidelines or baseline rules.**

- **Dynamic Grounding:** Specialized agents (e.g., Security Compliance and SRE Specialists) must not have static guidelines embedded directly within their system instruction prompts.
- **Systematic MCP Querying:** Agents must systematically query connected Model Context Protocol (MCP) server endpoints to retrieve up-to-date policy documents as grounding data.
- **Single Source of Truth:** All policy baselines must reside in designated policy repositories (e.g., the `./policies/` directory) and be queried dynamically at runtime via the MCP server's tools or resource lookups.
