# Log Rotation

The Wazuh Operator provides automated log rotation for manager pods through a Kubernetes CronJob. This feature helps manage disk space by automatically cleaning up old log files.

## Overview

When enabled, the operator creates a CronJob that periodically executes a cleanup script on all manager pods (master and workers). The script can delete files based on age, size, or both.

## Configuration

Log rotation is configured in the `manager.logRotation` section of the WazuhCluster spec:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.9.0"
  manager:
    logRotation:
      enabled: true
      schedule: "0 0 * * 1" # Weekly on Monday at midnight
      retentionDays: 7 # Delete files older than 7 days
      maxFileSizeMB: 100 # Delete files larger than 100MB
      combinationMode: "or" # Delete if old OR large
      paths:
        - /var/ossec/logs/alerts/
        - /var/ossec/logs/archives/
```

## Configuration Options

| Field             | Type     | Default                  | Description                            |
| ----------------- | -------- | ------------------------ | -------------------------------------- |
| `enabled`         | bool     | `false`                  | Enable log rotation CronJob            |
| `schedule`        | string   | `0 0 * * 1`              | Cron schedule expression               |
| `retentionDays`   | int32    | `7`                      | Number of days to retain log files     |
| `maxFileSizeMB`   | int32    | `0`                      | Maximum file size in MB (0 = disabled) |
| `combinationMode` | string   | `or`                     | How age and size filters combine       |
| `paths`           | []string | alerts/, archives/       | Log paths to clean                     |
| `image`           | string   | `bitnami/kubectl:latest` | kubectl image for CronJob              |

## Combination Modes

The `combinationMode` field controls how age and size filters work together:

- **`or`** (default): Delete files that are old OR large. This is more aggressive cleanup.
- **`and`**: Delete only files that are old AND large. This is more conservative.

### Examples

With `retentionDays: 7` and `maxFileSizeMB: 100`:

| Mode  | Behavior                                                                |
| ----- | ----------------------------------------------------------------------- |
| `or`  | Delete files older than 7 days, AND delete files larger than 100MB      |
| `and` | Delete only files that are both older than 7 days AND larger than 100MB |

## Schedule Format

The schedule uses standard cron format:

```
┌───────────── minute (0 - 59)
│ ┌───────────── hour (0 - 23)
│ │ ┌───────────── day of month (1 - 31)
│ │ │ ┌───────────── month (1 - 12)
│ │ │ │ ┌───────────── day of week (0 - 6) (Sunday to Saturday)
│ │ │ │ │
* * * * *
```

Common schedules:

- `0 0 * * *` - Daily at midnight
- `0 0 * * 0` - Weekly on Sunday
- `0 0 * * 1` - Weekly on Monday (default)
- `0 0 1 * *` - Monthly on the 1st
- `0 */6 * * *` - Every 6 hours

## Default Paths

By default, the following paths are cleaned:

- `/var/ossec/logs/alerts/` - Alert log files
- `/var/ossec/logs/archives/` - Archive log files

You can customize the paths to include other log directories:

```yaml
logRotation:
  enabled: true
  paths:
    - /var/ossec/logs/alerts/
    - /var/ossec/logs/archives/
    - /var/ossec/logs/api/
```

## How It Works

1. The operator creates a CronJob in the same namespace as the WazuhCluster
2. At the scheduled time, the CronJob runs a Job
3. The Job pod uses `kubectl exec` to run cleanup commands on each manager pod
4. Files matching the age/size criteria are deleted

The CronJob selects manager pods using the label:

```
app.kubernetes.io/component=wazuh-manager
```

This matches both master and worker manager pods.

## RBAC Requirements

The log rotation feature requires additional RBAC permissions. The operator's ServiceAccount needs:

- `pods/exec` permission to execute commands in manager pods
- `pods` list/get permission to find manager pods

These permissions are included in the operator's default RBAC configuration.

## Verifying Log Rotation

### Check CronJob Status

```bash
kubectl get cronjob -n wazuh
```

### Check Recent Jobs

```bash
kubectl get jobs -n wazuh -l app.kubernetes.io/component=log-rotation
```

### View Job Logs

```bash
# Get the most recent job
JOB=$(kubectl get jobs -n wazuh -l app.kubernetes.io/component=log-rotation \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')

# View logs
kubectl logs -n wazuh job/$JOB
```

### Manual Trigger

To test log rotation manually:

```bash
kubectl create job --from=cronjob/<cluster-name>-log-rotation manual-test -n wazuh
```

## Troubleshooting

### CronJob Not Running

1. Check the CronJob exists:

   ```bash
   kubectl get cronjob -n wazuh
   ```

2. Verify the schedule is correct:
   ```bash
   kubectl describe cronjob <cluster-name>-log-rotation -n wazuh
   ```

### Permission Errors

If jobs fail with permission errors:

1. Check RBAC permissions:

   ```bash
   kubectl auth can-i create pods/exec --as=system:serviceaccount:wazuh:wazuh-operator
   ```

2. Verify the ServiceAccount has the required ClusterRole bindings

### No Files Deleted

1. Check the retention settings match your expectations
2. Verify the paths are correct
3. Review the job logs for details on what files were evaluated
