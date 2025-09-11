# OTC Route Manager Makefile

# Variables
IMAGE_NAME ?= otc-route-manager
IMAGE_TAG ?= latest
REGISTRY ?= your-registry.com
NAMESPACE ?= otc-route-manager

# Go variables
GOCMD = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean
GOTEST = $(GOCMD) test
GOGET = $(GOCMD) get
GOMOD = $(GOCMD) mod

# Binary name
BINARY_NAME = otc-route-manager

.PHONY: all build clean test deps docker-build docker-push deploy undeploy help

# Default target
all: build

# Build the Go binary
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -a -installsuffix cgo -o $(BINARY_NAME) .

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

# Run tests
test:
	$(GOTEST) -v ./...

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build Docker image
docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Tag and push Docker image
docker-push: docker-build
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

# Create namespace and apply secrets/configmaps
setup-config:
	@echo "Setting up configuration..."
	@echo "Please update the Secret and ConfigMap with your actual values:"
	@echo "1. Edit the otc-credentials Secret with base64 encoded values"
	@echo "2. Edit the otc-route-manager-config ConfigMap with your OTC configuration"
	kubectl apply -f - <<< 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: $(NAMESPACE)'

# Deploy to OpenShift/Kubernetes
deploy:
	@echo "Deploying OTC Route Manager..."
	kubectl apply -f manifests.yaml
	@echo "Deployment complete. Check status with: kubectl get pods -n $(NAMESPACE)"

# Undeploy from OpenShift/Kubernetes
undeploy:
	kubectl delete -f manifests.yaml --ignore-not-found=true

# Show logs
logs:
	kubectl logs -f daemonset/otc-route-manager -n $(NAMESPACE)

# Show status
status:
	kubectl get all -n $(NAMESPACE)
	kubectl get nodes -o wide

# Port forward for local access to metrics
port-forward:
	kubectl port-forward service/otc-route-manager-metrics 8080:8080 -n $(NAMESPACE)

# Restart DaemonSet
restart:
	kubectl rollout restart daemonset/otc-route-manager -n $(NAMESPACE)

# Create secrets interactively
create-secrets:
	@echo "Creating OTC credentials secret..."
	@read -p "Enter OS_USERNAME: " username; \
	read -s -p "Enter OS_PASSWORD: " password; echo; \
	read -p "Enter OS_PROJECT_NAME: " project; \
	read -p "Enter OS_DOMAIN_NAME: " domain; \
	kubectl create secret generic otc-credentials \
		--from-literal=OS_USERNAME=$$username \
		--from-literal=OS_PASSWORD=$$password \
		--from-literal=OS_PROJECT_NAME=$$project \
		--from-literal=OS_DOMAIN_NAME=$$domain \
		-n $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -

# Create configmap interactively
create-configmap:
	@echo "Creating OTC route manager configuration..."
	@read -p "Enter ROUTE_TABLE_ID: " route_table_id; \
	read -p "Enter VPC_SUBNET_ID: " vpc_subnet_id; \
	read -p "Enter ROUTER_ID: " router_id; \
	read -p "Enter CLUSTER_CIDR (e.g., 10.244.0.0/16): " cluster_cidr; \
	read -p "Enter SERVICE_CIDR (e.g., 10.96.0.0/12): " service_cidr; \
	kubectl create configmap otc-route-manager-config \
		--from-literal=OS_AUTH_URL="https://iam.eu-de.otc.t-systems.com/v3" \
		--from-literal=OS_REGION_NAME="eu-de" \
		--from-literal=ROUTE_TABLE_ID=$$route_table_id \
		--from-literal=VPC_SUBNET_ID=$$vpc_subnet_id \
		--from-literal=ROUTER_ID=$$router_id \
		--from-literal=CLUSTER_CIDR=$$cluster_cidr \
		--from-literal=SERVICE_CIDR=$$service_cidr \
		--from-literal=METRICS_PORT="8080" \
		-n $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -

# Full setup (interactive)
setup: setup-config create-secrets create-configmap deploy

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the Go binary"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  deps           - Download and tidy dependencies"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-push    - Build and push Docker image"
	@echo "  setup-config   - Create namespace"
	@echo "  create-secrets - Create secrets interactively"
	@echo "  create-configmap - Create configmap interactively"
	@echo "  setup          - Full interactive setup"
	@echo "  deploy         - Deploy to cluster"
	@echo "  undeploy       - Remove from cluster"
	@echo "  logs           - Show logs"
	@echo "  status         - Show deployment status"
	@echo "  port-forward   - Port forward metrics (8080)"
	@echo "  restart        - Restart DaemonSet"
	@echo "  help           - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  IMAGE_NAME     - Docker image name (default: $(IMAGE_NAME))"
	@echo "  IMAGE_TAG      - Docker image tag (default: $(IMAGE_TAG))"
	@echo "  REGISTRY       - Docker registry (default: $(REGISTRY))"
	@echo "  NAMESPACE      - Kubernetes namespace (default: $(NAMESPACE))"
	