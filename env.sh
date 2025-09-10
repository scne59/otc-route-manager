# Kubernetes config
export KUBECONFIG="/path/to/kubeconfig"  # Optional, uses in-cluster config if not set
#export NODE_NAME="specific-node"         # Optional, processes all nodes if not set

# OpenStack/OTC credentials
export OS_AUTH_URL="https://iam.eu-de.otc.t-systems.com/v3"
export OS_USER_DOMAIN_NAME="OTC-EU-DE-00000000000000000"
export OS_USERNAME="username"
export OS_PASSWORD="password"
export OS_DOMAIN_NAME="OTC-EU-DE-0000000000000000"
export OS_PROJECT_NAME="eu-de_project"
export OS_REGION_NAME="eu-de"

# VPC/Network config
export ROUTE_TABLE_ID="a18094cf-5561-4d71-85c7-3a9b74f4b7c2"

export CLUSTER_CIDR="192.168.0.0/16"
export SERVICE_CIDR="172.30.0.0/16"
