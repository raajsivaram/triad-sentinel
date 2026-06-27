import logging
import re

logger = logging.getLogger(__name__)

def analyze_stride(components_text: str) -> str:
    """
    Exposes a Python function to map input text architecture components 
    against the STRIDE threat modeling framework:
    - S: Spoofing (e.g. Identity, credentials, authentication)
    - T: Tampering (e.g. Data integrity, encryption, hashing)
    - R: Repudiation (e.g. Auditing, logs, non-repudiation)
    - I: Information Disclosure (e.g. Confidentiality, leaks, secrets)
    - D: Denial of Service (e.g. Availability, scaling, rate limiting)
    - E: Elevation of Privilege (e.g. Authorization, RBAC, root permissions)

    Args:
        components_text (str): The architectural proposal or components description.

    Returns:
        str: A Markdown-formatted threat modeling report listing identified 
             components, potential threats mapped to STRIDE, and suggested mitigations.

    Raises:
        None
    """
    logger.info("Executing STRIDE threat modeling analysis on components_text.")

    # 1. Initialize result structure and threats catalog
    report_sections = []
    
    # 2. Normalize and check if input is empty
    if not components_text or not components_text.strip():
        return "### ⚠️ STRIDE Threat Model Analysis\nNo architectural components provided for analysis."

    # 3. Define the component detection regexes and their corresponding STRIDE threat mappings
    component_rules = [
        {
            "name": "Database / Storage System (e.g., SQL, S3, GCS, Cloud SQL)",
            "keywords": [r"\bdatabas\w*", r"\bdb\b", r"\bsql\b", r"\bs3\b", r"\bbucket\b", r"\bstorag\w*", r"\bpostgre\w*", r"\bmongo\w*"],
            "threats": [
                {
                    "category": "Tampering",
                    "description": "Unauthorized modification of database schemas or storage files if access controls are weak or encryption is missing.",
                    "mitigation": "Enable Row-Level Security (RLS), enforce AES-256 encryption at rest, and use multi-factor authentication for administrative operations."
                },
                {
                    "category": "Information Disclosure",
                    "description": "Exposure of sensitive customer data or database secrets if storage buckets are misconfigured as public or plaintext data is leaked.",
                    "mitigation": "Implement TLS 1.3 for data in transit, restrict public access policies, and apply tokenization/masking on sensitive columns."
                },
                {
                    "category": "Denial of Service",
                    "description": "Exhaustion of database connection pools or storage quotas, causing service downtime during traffic spikes.",
                    "mitigation": "Configure connection pooling (e.g. pgBouncer), implement read replicas, and establish resource quotas/auto-scaling storage."
                }
            ]
        },
        {
            "name": "Frontend / Web Server (e.g., UI, Nginx, Apache, App Engine)",
            "keywords": [r"\bfront\w*", r"\bweb\w*", r"\bnginx\b", r"\bapache\b", r"\bui\b", r"\bserver\b", r"\bapp\w*"],
            "threats": [
                {
                    "category": "Spoofing",
                    "description": "User impersonation or session hijacking if session tokens lack secure/HttpOnly flags or CSRF protection is missing.",
                    "mitigation": "Use secure HTTP cookies with SameSite, HttpOnly, and Secure flags, and enforce OAuth2/OIDC standards."
                },
                {
                    "category": "Denial of Service",
                    "description": "Application crash or slowness under volumetric HTTP requests (DDoS) without appropriate rate limiting.",
                    "mitigation": "Deploy a Cloud CDN, configure Cloud Armor or Web Application Firewall (WAF), and apply rate-limiting at ingress."
                },
                {
                    "category": "Elevation of Privilege",
                    "description": "Execution of arbitrary command injections if input validation is missing on frontend forms or API parameters.",
                    "mitigation": "Implement strict input validation schemas, sanitize all user inputs, and run web server processes under least-privilege service accounts."
                }
            ]
        },
        {
            "name": "API Gateway / Load Balancer (e.g., Ingress, Envoy, Kong, ALB)",
            "keywords": [r"\bgateway\b", r"\bproxy\b", r"\bingress\b", r"\bload\s*balanc\w*", r"\balb\b", r"\benvoy\b"],
            "threats": [
                {
                    "category": "Spoofing",
                    "description": "Man-in-the-Middle (MITM) attacks if client-to-gateway traffic is unencrypted or uses weak SSL/TLS cipher suites.",
                    "mitigation": "Enforce HTTPS/TLS 1.3, configure secure HTTP headers (HSTS), and implement Mutual TLS (mTLS) for internal service communications."
                },
                {
                    "category": "Tampering",
                    "description": "Modification of API request payloads or header injection attacks bypassing gateway route logic.",
                    "mitigation": "Implement API schema validation at the gateway level and cryptographically sign headers/tokens (e.g., JWT signatures)."
                }
            ]
        },
        {
            "name": "Authentication & IAM Service (e.g., Keycloak, Cognito, Active Directory)",
            "keywords": [r"\bauth\w*", r"\blogin\b", r"\biam\b", r"\bkeycloak\b", r"\bcognito\b", r"\bidentity\b", r"\boauth\b", r"\bsso\b"],
            "threats": [
                {
                    "category": "Spoofing",
                    "description": "Brute-force credential stuffing or bypass of weak authentication policies leading to account takeover.",
                    "mitigation": "Enforce strong password complexity rules, mandate Multi-Factor Authentication (MFA), and implement account lockout policies."
                },
                {
                    "category": "Repudiation",
                    "description": "Lack of traceability for critical administrative events (e.g. role updates) if audit logging is disabled or mutable.",
                    "mitigation": "Ship all IAM and authentication logs to an immutable write-once-read-many (WORM) storage bucket with centralized alerting."
                },
                {
                    "category": "Elevation of Privilege",
                    "description": "Vertical privilege escalation if users can modify their own role parameters or if default roles are overly permissive.",
                    "mitigation": "Follow Least Privilege principles, separate administrator roles, and use Attribute-Based or Role-Based Access Control (RBAC)."
                }
            ]
        },
        {
            "name": "Message Queue / Event Bus (e.g., Pub/Sub, Kafka, RabbitMQ)",
            "keywords": [r"\bqueu\w*", r"\bkafka\b", r"\bpub\s*/\s*sub\b", r"\bpubsub\b", r"\brabbit\w*", r"\bbus\b"],
            "threats": [
                {
                    "category": "Tampering",
                    "description": "Poison message injection or queue state corruption if publish endpoints are not authenticated.",
                    "mitigation": "Enforce strict IAM publishing permissions and perform payload validation before message ingestion."
                },
                {
                    "category": "Information Disclosure",
                    "description": "Plaintext broker payload inspection by unauthorized consumers sharing the network segment.",
                    "mitigation": "Encrypt payload fields containing PII or sensitive data before sending them to the message broker."
                }
            ]
        }
    ]

    # 4. Perform keyword-based matching to extract components
    detected_components = []
    normalized_input = components_text.lower()
    
    for rule in component_rules:
        # Check if any keyword matches the input architecture text
        match_found = False
        for kw in rule["keywords"]:
            if re.search(kw, normalized_input):
                match_found = True
                break
        
        if match_found:
            detected_components.append(rule)

    # 5. Build the threat report in Markdown
    report_sections.append("## 🛡️ STRIDE THREAT MODELING ANALYSIS REPORT")
    report_sections.append("This report dynamically maps identified architecture components against the STRIDE threat modeling framework to highlight critical security vectors.")
    
    if not detected_components:
        report_sections.append("\n> [!NOTE]\n> No specific specialized components (Database, Frontend, API Gateway, Auth, Queue) were explicitly recognized via regex. Defaulting to general system architecture threats.")
        # Provide a general STRIDE fallback mapping
        report_sections.append("### General System Architecture threats:")
        report_sections.append("* **Tampering / Info Disclosure:** Ensure all inter-service communications are encrypted in transit via TLS 1.3 and at rest using AES-256.")
        report_sections.append("* **Denial of Service:** Establish rate-limiting, autoscaling compute policies, and active load balancing gateways.")
    else:
        for idx, comp in enumerate(detected_components, 1):
            report_sections.append(f"\n### {idx}. Component: {comp['name']}")
            
            # Create a Markdown table for clean rendering of STRIDE mapping
            report_sections.append("| STRIDE Category | Threat Description | Mitigation Strategy |")
            report_sections.append("|---|---|---|")
            for t in comp["threats"]:
                report_sections.append(f"| **{t['category']}** | {t['description']} | {t['mitigation']} |")

    return "\n".join(report_sections)
