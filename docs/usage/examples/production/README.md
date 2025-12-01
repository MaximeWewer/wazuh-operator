# Production Deployment Guide

This directory contains production-ready configurations for deploying Wazuh clusters.

## Overview

The production configuration includes:

- High availability with multiple replicas
- Log rotation for automated cleanup
- Proper resource allocation
- Pod disruption budgets
- Node selectors for dedicated nodes
- Email alerting configuration

## Prerequisites

- Kubernetes cluster with sufficient resources (see resource requirements below)
- Storage class supporting dynamic provisioning
- Dedicated nodes labeled with `node-role.kubernetes.io/wazuh: "true"` (optional)
- SMTP server for email alerts (optional)

## Resource Requirements

| Component            | CPU Request | Memory Request | Storage    |
| -------------------- | ----------- | -------------- | ---------- |
| Manager Master       | 1000m       | 2Gi            | 100Gi      |
| Manager Workers (x3) | 1000m each  | 2Gi each       | 100Gi each |
| Indexer (x3)         | 2000m each  | 8Gi each       | 500Gi each |
| Dashboard (x2)       | 500m each   | 1Gi each       | -          |
| **Total**            | **~13 CPU** | **~38Gi**      | **~1.9Ti** |

## Deployment Steps

### 1. Create Namespace

```bash
kubectl create namespace wazuh
```

### 2. Create Secrets

Edit `secrets.yaml` to set secure passwords, then apply:

```bash
# IMPORTANT: Change the passwords before applying!
kubectl apply -f secrets.yaml
```

### 3. Deploy Cluster

```bash
kubectl apply -f wazuh-cluster.yaml
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

Configure your SMTP server in `wazuh-cluster.yaml`:

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
