# Corporate FinOps Baselines for Google Cloud Platform (GCP)

These guidelines define the mandatory cost optimization standards for all Google Cloud Platform infrastructure layouts, resource provisioning, and deployment templates.

## Compute Engine (GCE) Optimization

### Mandatory Elastic Provisioning
* **Managed Instance Groups (MIGs) with Autoscaling:** All stateless web, application, or API serving workloads must be deployed within Managed Instance Groups (MIGs) configured with dynamic autoscaling policies based on CPU utilization (target 60-70%) or custom Pub/Sub or HTTP metrics. Static, standalone Compute Engine instances are prohibited for stateless services.

### Machine Family Optimization
* **Avoid General-Purpose N1 Instances:** Provisioning general-purpose N1 machine types is strictly restricted due to higher baseline cost-to-performance ratios.
* **Mandated Machine Families:** Workloads must use:
  * **E2 Family:** For cost-optimized, low-to-medium utilization applications, development environments, and small utilities.
  * **N2/N2D/C3 Families:** For production workloads requiring high performance, predictable throughput, or local SSD attachments.

### Fault-Tolerant Compute
* **Spot VMs for Batch Processing:** Fault-tolerant batch computing, offline data processing, research workloads, and asynchronous worker tasks (e.g., in Dataflow pipelines or GKE batch jobs) must utilize Spot VMs (formerly Preemptible VMs) to save up to 60-90% on compute unit charges.

### Predictable Workload Commitments
* **Committed Use Discounts (CUDs):** Predictable baseline workloads running continuously for 1 to 3 years must be covered by Resource-Based or Flexible Committed Use Discounts (CUDs) rather than paying standard on-demand rates.

## Cloud Storage & Database Lifecycle

### Cloud Storage Lifecycle Policies
* **Mandatory Object Lifecycle Management:** All Cloud Storage (GCS) buckets must have explicit Lifecycle Management rules configured:
  * Transition objects from Standard storage to Nearline storage after 30 days of inactivity.
  * Transition objects to Coldline or Archive storage after 90 days of inactivity.
  * Define explicit deletion policies for temporary data, logs, and staging buckets.

### Storage Volumetric Management
* **Unattached Persistent Disks:** Unattached Persistent Disks (both PD-Standard and PD-SSD) must be flagged and handled within 7 days of detaching. An automated scheduler must delete these disks or take a final snapshot and delete the volume to eliminate persistent compute storage overhead.

### Environment Scheduling
* **Off-Hours Scheduling for Non-Production:** Non-production Cloud SQL instances and GKE Node Pools must be configured with an automated scheduler (e.g., using Cloud Scheduler and Cloud Functions) to stop/scale-down to 0 nodes during off-hours (evenings and weekends), minimizing idle runtime costs.

## Network Cost Controls

### Egress Cost Mitigation
* **Cloud CDN Usage:** All public-facing static assets, media files, and cacheable API responses must serve traffic through Cloud CDN to reduce external network egress costs.
* **Keep Traffic Local:** Internal inter-service traffic must stay within the same region and VPC network. Avoid crossing regions or external internet pathways for internal data transfers by utilizing VPC Service Controls, Private Service Connect (PSC), or Private Google Access.

### NAT Gateway Provisioning
* **Minimize Cloud NAT Redundancy:** Avoid provisioning redundant Cloud NAT gateways within the same region/VPC when a single, highly-available Cloud NAT configuration can serve all subnets. Cloud NAT incurs per-gateway uptime costs and per-GB data processing fees.

## Idle Resource Detection

### IP Address Allocation
* **Flag Unallocated Static IP Addresses:** Static external IP addresses that are reserved but unattached to active VM instances or load balancers must be identified and released immediately, as Google Cloud charges hourly rates for unused external IPs.

### Load Balancer Utilization
* **Identify Idle Load Balancers:** Flag any Cloud Load Balancer (HTTPS, TCP/UDP internal/external) that processes fewer than 100 requests over a rolling 7-day period.

### Image & Snapshot Cleanup
* **Orphaned Images and Snapshots:** Flag and remove old, orphaned machine images and VM snapshots (older than 90 days) unless required by explicit corporate data retention compliance policies.
