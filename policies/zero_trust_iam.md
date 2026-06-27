# Corporate Zero-Trust IAM & Security Perimeter Guidelines

These compliance rules serve as the official standard for evaluating infrastructure designs:

1. **Identity & Access Management (GCP IAM):** Enforce the Principle of Least Privilege using custom GCP IAM roles, strictly avoiding basic/primitive roles such as `roles/editor` or `roles/owner`. Look for administrative or resource wildcards (*), over-privileged policies, or lack of explicit Role-Based Access Control (RBAC).
2. **Data Perimeter Isolation:** Verify that public Cloud Storage (GCS) buckets are banned. Enforce data perimeters using VPC Service Controls (VPC-SC). Mandate data-at-rest encryption using Customer-Managed Encryption Keys (CMEK) via Cloud KMS, and enforce transport encryption (TLS 1.3).
3. **Network Defense:** Ensure zero-exposure to public routing tables. Look for misconfigured subnets, public SSH/RDP ports open to 0.0.0.0/0, and verify that secure API gateways or transit gateways are present.
