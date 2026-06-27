# Corporate SRE Compute & Reliability Guidelines

These reliability standards serve as the official standard for evaluating infrastructure designs:

1. **High Availability (HA) & Fault Tolerance:** Look for single points of failure (SPOFs). Ensure multi-region or multi-zone topologies are explicitly configured for core computing (utilizing Regional Managed Instance Groups (MIGs)), database replication (utilizing Cloud Spanner for global relational HA or highly available Cloud SQL), caching HA (utilizing Cloud Memorystore/Redis), and traffic routing.
2. **Elastic Auto-Scaling & Resource Guardrails:** Check for clear compute thresholds, target tracking policies, and explicit resource allocations (CPU/Memory limits) to prevent runaway microservices or GCE/GKE cluster starvation.
3. **Observability & Telemetry:** Verify that structured logging, distributed tracing parameters, and metrics collection targets are explicitly declared across all network and compute components utilizing Cloud Monitoring and Cloud Trace for full observability.
4. **Cost Efficiency & Lifecycle Management:** Identify bloated over-provisioning (e.g., static massive GCE instances with zero elastic pooling). Verify that storage tiers utilize object-lifecycle rules to transition cold data in GCS down to Archive/Coldline storage.
