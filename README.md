# OTC Route Manager - OpenShift/Kubernetes Deployment/DaemonSet

The **OTC Route Manager** is a Kubernetes program that automatically manages VPC routes for cluster pod network traffic in the Open Telekom Cloud (OTC). It runs on worker nodes and creates or updates routes to direct cluster pod traffic to the appropriate ECS instances.

## Features

- **Cluster Pod Traffic Only:** Manages routes exclusively for cluster pod CIDRs.
- **Worker Node Targeting:** Runs only on worker nodes; master/control-plane nodes are ignored.
- **Safe Route Management:** Never modifies default routes (`0.0.0.0/0`) or non-cluster routes.
- **Prometheus Metrics:** Exposes metrics for monitoring and alerting.
- **OpenShift Security:** Follows OpenShift security best practices with restricted security contexts.
- **High Availability:** Runs as a DaemonSet with health checks and supports rolling updates.

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
│                                │                       │
└────────────────────────────────┼───────────────────────┘
                                 │
                     ┌─────────────────────┐
                     │   OTC VPC Router    │
                     │   Route Table       │
                     │                     │
                     │ 192.168.1.0/24 →    │
                     │   node-1-instance   │
                     │ 192.168.2.0/24 →    │
                     │   node-2-instance   │
                     │ 192.168.3.0/24 →    │
                     │   node-3-instance   │
                     └─────────────────────┘

```

## Prerequisites

1. **OpenShift/Kubernetes Cluster:** Running on OTC with worker nodes provisioned as ECS instances.
2. **OTC Credentials:** Service account with necessary VPC and ECS permissions.
3. **Network Configuration:** 
   - VPC configured with a route table.
   - Worker nodes annotated with `k8s.ovn.org/node-subnets` containing cluster pod CIDRs.
4. **Container Registry:** To store and pull the built container image.

## Quick Start

### 1. Build and Push the Image

```


# Clone the repository and navigate to its root directory

# Confirm Go source code and Dockerfile are present

# Build the Docker image

make docker-build IMAGE_NAME=your-registry.com/otc-route-manager IMAGE_TAG=v1.0.0

# Push the image to your registry

make docker-push REGISTRY=your-registry.com IMAGE_TAG=v1.0.0

```

### 2. Configure Deployment

Edit the manifests to customize your setup:

```


# Recommended interactive setup

make setup

# Or manual configuration:

# 1. Update image reference in manifests.yaml

# 2. Edit secrets and configmaps with your credentials and configuration values

```

### 3. Deploy the Application

```


# Deploy all resources

make deploy

# Verify deployment status

make status

```

## Configuration

### Environment Variables

| Variable         | Description                | Example                              | Required |
|------------------|----------------------------|------------------------------------|----------|
| `OS_USERNAME`    | OTC username               | `your-username`                    | ✅       |
| `OS_PASSWORD`    | OTC password               | `your-password`                    | ✅       |
| `OS_PROJECT_NAME`| OTC project name           | `eu-de`                           | ✅       |
| `OS_DOMAIN_NAME` | OTC domain name            | `OTC00000000001000000xxx`          | ✅       |
| `OS_AUTH_URL`    | OTC identity endpoint      | `https://iam.eu-de.otc.t-systems.com/v3` | ✅       |
| `OS_REGION_NAME` | OTC region                 | `eu-de`                           | ✅       |
| `ROUTE_TABLE_ID` | VPC route table ID         | `b18094bf-4761-4d71-85c7-3a9b74f4b7c8` | ✅       |
| `CLUSTER_CIDR`   | Pod network CIDRs          | `192.168.0.0/16`                   | ✅       |
| `METRICS_PORT`   | Port for metrics server    | `8080`                           | ❌       |

### OTC Permissions

The service account needs the following OTC permissions:

```

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

The deployment complies with OpenShift security best practices:

- Runs containers as non-root user **1001**.
- Root filesystem is **read-only**.
- No privileged escalation; all Linux capabilities are dropped.
- Restricted security contexts applied.
- Compatible with the OpenShift and Kubernetes Pod Security Standards at the **restricted** level.

## Monitoring

### Metrics

- Exposes Prometheus-compatible metrics on the configured port (default `8080`).
- Key metric: `route_manager_nodes_processed_total{status="success|error|skipped"}` indicates processed node counts with status.

### Health Checks

- **Liveness Probe:** HTTP GET on `/health` endpoint.
- **Readiness Probe:** HTTP GET on `/health` endpoint.

### Prometheus Integration

Includes a `ServiceMonitor` resource for easy integration with the Prometheus Operator.

## Troubleshooting

### Common Issues

1. **Authentication Errors**
```

kubectl get secret otc-credentials -n otc-route-manager -o yaml
make logs

```

2. **Route Creation Failures**
```

kubectl get configmap otc-route-manager-config -n otc-route-manager -o yaml
kubectl get nodes -o yaml | grep -A 10 "k8s.ovn.org/node-subnets"

```

3. **Permission Issues**
```

kubectl auth can-i list nodes --as=system:serviceaccount:otc-route-manager:otc-route-manager

```

### Debug Commands

```

make logs
kubectl get pods -n otc-route-manager -o wide
kubectl describe daemonset otc-route-manager -n otc-route-manager
make port-forward

# Then visit http://localhost:8080/metrics

kubectl get nodes --show-labels | grep worker

```

### Log Messages

- `✅ Success`: Successfully processed node.
- `ℹ️ Info`: Skipping route; not cluster traffic.
- `⚠️ Warning`: Skipping node; subnet not cluster traffic.
- `❌ Error`: Failed to create or update route.

## Maintenance

### Update Configuration

```

make create-secrets
make create-configmap
make restart  \# Restart DaemonSet to apply changes

```

### Update Image

```

make docker-build IMAGE_TAG=v1.1.0
make docker-push IMAGE_TAG=v1.1.0

# Update image reference in manifests.yaml

make deploy

```

## Uninstallation

```

make undeploy  \# Remove all resources deployed by this manager

```

## Development

### Local Testing

```

make deps       \# Install dependencies
make test       \# Run tests
make build      \# Build locally

```

### Contributing

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes.
4. Add appropriate tests.
5. Submit a pull request.

## License

MIT License © 2025 Jochen Schneider

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.