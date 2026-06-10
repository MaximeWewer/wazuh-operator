# Production Deployment Guide

This directory contains production-ready configurations for deploying Wazuh clusters.

## Overview

The production configuration includes:

- High availability with multiple replicas
- Pod anti-affinity (indexer spread required, manager preferred) + pod disruption budgets
- Prometheus monitoring (indexer + Wazuh exporters, ServiceMonitor)
- TLS with hot reload (cert renewal without pod restart)
- Dedicated storage class and node selectors for dedicated nodes
- Log rotation for automated cleanup
- Email alerting configuration

## Prerequisites

- Kubernetes cluster with sufficient resources (see resource requirements below)
- A StorageClass named `fast-ssd` (or edit `spec.storageClassName` in the manifest)
- Dedicated nodes labeled with `node-role.kubernetes.io/wazuh: "true"` (optional)
- Prometheus Operator CRDs, for the `ServiceMonitor` (optional — disable if absent)
- SMTP server for email alerts (optional)
- A secrets workflow (External Secrets, Vault, Sealed Secrets) — the inline
  Secrets in the manifest are placeholders to replace, not commit

## Resource Requirements

| Component            | CPU Request | Memory Request | Storage    |
| -------------------- | ----------- | -------------- | ---------- |
| Manager Master       | 1000m       | 2Gi            | 100Gi      |
| Manager Workers (x3) | 1000m each  | 2Gi each       | 100Gi each |
| Indexer (x3)         | 2000m each  | 16Gi each      | 500Gi each |
| Dashboard (x2)       | 500m each   | 1Gi each       | -          |
| **Total**            | **~13 CPU** | **~58Gi**      | **~1.9Ti** |

> Indexer memory request equals its limit (16Gi) for Guaranteed QoS, with JVM
> heap set to 50% (8g). Adjust to your data volume; reduce for smaller setups.

## Two example manifests

This directory has two **independent** examples — apply one, not both:

- **`wazuhcluster-production.yaml`** (cluster `wazuh-production`) — the main
  production reference. Self-contained: the cluster plus its placeholder
  Secrets in one file.
- **`secrets-inline.yaml`** (cluster `wazuh-secure`) — an alternative that
  demonstrates inline-credential mode (Secrets + OpenSearch users wired into
  the cluster). See [Credentials](../../features/credentials.md).

## Deployment Steps

### 1. Create Namespace

```bash
kubectl create namespace wazuh
```

### 2. Replace the placeholder passwords

Edit the Secret values in `wazuhcluster-production.yaml`
(`REPLACE_WITH_...`). In real production, manage these with a secrets operator
(External Secrets, Vault, Sealed Secrets) and delete the inline Secret blocks.

### 3. Deploy Cluster

```bash
kubectl apply -f wazuhcluster-production.yaml
```

### 4. Monitor Deployment

```bash
kubectl get wazuhcluster -n wazuh -w
kubectl get pods -n wazuh -w
```

## Configuration Highlights

### Log Rotation

Automated log cleanup is configured:

- Schedule: Weekly on Sunday at midnight
- Retention: 30 days
- Max file size: 500MB
- Paths: `/var/ossec/logs/alerts/`, `/var/ossec/logs/archives/`

### Email Alerts

Configure your SMTP server in `wazuhcluster-production.yaml`:

```yaml
global:
  emailNotification: true
  smtpServer: "smtp.internal.company.com"
  emailFrom: "wazuh@company.com"
  emailTo: "soc@company.com"
```

### Ingress

The production example includes ingress configuration for the dashboard:

```yaml
ingress:
  enabled: true
  ingressClassName: "nginx"
  hosts:
    - host: wazuh.company.com
```

## Security Considerations

1. **Change all default passwords** before deployment
2. Use Kubernetes secrets or external secret management
3. Enable network policies to restrict traffic
4. Use TLS for all communications (enabled by default)
5. Regularly rotate certificates

## Backup Strategy

1. **Indexer data**: Use OpenSearchSnapshotPolicy CRD for automated backups
2. **Configuration**: Store WazuhCluster YAML in version control
3. **Secrets**: Use external secret management (HashiCorp Vault, AWS Secrets Manager)

## Troubleshooting

See [quick-start/02-verify-deployment.md](../quick-start/02-verify-deployment.md) for common troubleshooting steps.
