# OTC Route Manager - OpenShift/Kubernetes Deployment/Daemonset
 
The OTC Route Manager is a Kubernetes program that automatically manages VPC routes for cluster network traffic in Open Telekom Cloud (OTC). It runs on worker nodes and creates/updates routes to direct cluster and service traffic to the appropriate ECS instances.

## Features

- **Cluster Traffic Only**: Only manages routes for cluster pod CIDRs and service CIDRs
- **Worker Node Targeting**: Runs only on worker nodes, ignoring master/control-plane nodes
- **Safe Route Management**: Never touches default routes (0.0.0.0/0) or non-cluster routes
- **Prometheus Metrics**: Exposes metrics for monitoring and alerting
- **OpenShift Security**: Follows OpenShift security best practices with restricted security contexts
- **High Availability**: Can runs as a DaemonSet with proper health checks and rolling updates

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Worker Node   │    │   Worker Node   │    │   Worker Node   │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Route Mgr   │ │    │ │ Route Mgr   │ │    │ │ Route Mgr   │ │
│ │ Pod         │ │    │ │ Pod         │ │    │ │ Pod         │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────────┐
                    │   OTC VPC Router    │
                    │   Route Table       │
                    │                     │
                    │ 10.244.1.0/24 →     │
                    │   node-1-instance   │
                    │ 10.244.2.0/24 →     │
                    │   node-2-instance   │
                    │ 10.244.3.0/24 →     │
                    │   node-3-instance   │
                    └─────────────────────┘
```

## Prerequisites

1. **OpenShift/Kubernetes Cluster**: Running on OTC with worker nodes as ECS instances
2. **OTC Credentials**: Service account with VPC and ECS permissions
3. **Network Configuration**: 
   - VPC with route table
   - Worker nodes with `k8s.ovn.org/node-subnets` annotations
4. **Container Registry**: To store the built image

## Quick Start

### 1. Build and Push Image

```bash
# Clone the repository and navigate to it
# Ensure the Go source code and Dockerfile are in the current directory

# Build the Docker image
make docker-build IMAGE_NAME=your-registry.com/otc-route-manager IMAGE_TAG=v1.0.0

# Push to your registry
make docker-push REGISTRY=your-registry.com IMAGE_TAG=v1.0.0
```

### 2. Configure Deployment

Edit the manifests to include your configuration:

```bash
# Interactive setup (recommended)
make setup

# Or manually edit the files:
# 1. Update the image reference in manifests.yaml
# 2. Configure secrets and configmaps with your values
```

### 3. Deploy

```bash
# Apply all manifests
make deploy

# Check deployment status
make status
```

## Configuration

### Environment Variables

| Variable | Description | Example | Required |
|----------|-------------|---------|----------|
| `OS_USERNAME` | OTC username | `your-username` | ✅ |
| `OS_PASSWORD` | OTC password | `your-password` | ✅ |
| `OS_PROJECT_NAME` | OTC project name | `eu-de` | ✅ |
| `OS_DOMAIN_NAME` | OTC domain name | `OTC00000000001000000xxx` | ✅ |
| `OS_AUTH_URL` | OTC identity endpoint | `https://iam.eu-de.otc.t-systems.com/v3` | ✅ |
| `OS_REGION_NAME` | OTC region | `eu-de` | ✅ |
| `ROUTE_TABLE_ID` | VPC route table ID | `b18094bf-4761-4d71-85c7-3a9b74f4b7c8` | ✅ |
| `CLUSTER_CIDR` | Pod network CIDRs | `10.244.0.0/16` | ✅ |
| `SERVICE_CIDR` | Service network CIDRs | `10.96.0.0/12` | ✅ |
| `METRICS_PORT` | Metrics server port | `8080` | ❌ |

### OTC Permissions

The service account needs the following OTC permissions:

```json
{
  "Version": "1.1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:cloudServers:list",
        "ecs:cloudServers:get",
        "vpc:routeTables:get",
        "vpc:routeTables:update",
        "iam:projects:listProjects"
      ],
      "Resource": "*"
    }
  ]
}
```

## Security

The deployment follows OpenShift security best practices:

- **Non-root containers**: Runs as user 1001
- **Read-only filesystem**: Root filesystem is read-only
- **No privileged access**: All capabilities dropped
- **Security contexts**: Restricted security contexts applied
- **Pod Security Standards**: Compatible with restricted pod security

## Monitoring

### Metrics

The route manager exposes Prometheus metrics on port 8080:

- `route_manager_nodes_processed_total{status="success|error|skipped"}`: Number of nodes processed

### Health Checks

- **Liveness Probe**: `/health` endpoint on port 8080
- **Readiness Probe**: `/health` endpoint on port 8080

### ServiceMonitor

A ServiceMonitor is included for Prometheus Operator integration.

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   ```bash
   # Check credentials
   kubectl get secret otc-credentials -n otc-route-manager -o yaml
   
   # Verify OTC connectivity
   make logs
   ```

2. **Route Creation Failures**
   ```bash
   # Check route table configuration
   kubectl get configmap otc-route-manager-config -n otc-route-manager -o yaml
   
   # Verify node annotations
   kubectl get nodes -o yaml | grep -A 10 "k8s.ovn.org/node-subnets"
   ```

3. **Permission Issues**
   ```bash
   # Check RBAC
   kubectl auth can-i list nodes --as=system:serviceaccount:otc-route-manager:otc-route-manager
   ```

### Debugging Commands

```bash
# View logs
make logs

# Check pod status
kubectl get pods -n otc-route-manager -o wide

# Describe DaemonSet
kubectl describe daemonset otc-route-manager -n otc-route-manager

# Port forward for metrics
make port-forward
# Then visit http://localhost:8080/metrics

# Check node selector matching
kubectl get nodes --show-labels | grep worker
```

### Log Analysis

Look for these log patterns:

- `✅ Success`: `Successfully processed node`
- `ℹ️ Info`: `Skipping route X: not cluster traffic`
- `⚠️ Warning`: `Skipping node X: subnet Y is not cluster traffic`
- `❌ Error`: `Error processing node X: failed to create/update route`

## Maintenance

### Updating Configuration

```bash
# Update secrets
make create-secrets

# Update configmap
make create-configmap

# Restart DaemonSet to pick up changes
make restart
```

### Image Updates

```bash
# Build new image
make docker-build IMAGE_TAG=v1.1.0

# Push new image
make docker-push IMAGE_TAG=v1.1.0

# Update deployment (edit manifests.yaml first)
make deploy
```

## Uninstallation

```bash
# Remove all resources
make undeploy
```

## Development

### Local Testing

```bash
# Install dependencies
make deps

# Run tests
make test

# Build locally
make build
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the Apache License 2.0.