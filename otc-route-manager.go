package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config holds the configuration for the route manager
type Config struct {
	// Kubernetes config
	KubeConfigPath string
	NodeName       string

	// Open Telekom Cloud config
	IdentityEndpoint string
	Username         string
	Password         string
	DomainName       string
	ProjectName      string
	Region           string

	// VPC/Network config
	RouteTableID string
	MetricsPort  string
	ClusterCIDR  string

	// Daemonset mode configuration
	IsDaemonset    bool
	UpdateInterval time.Duration
}

// RouteManager manages VPC routes for Kubernetes nodes
type RouteManager struct {
	config        *Config
	kubeClient    kubernetes.Interface
	otcClient     *gophercloud.ServiceClient
	computeClient *gophercloud.ServiceClient
	identityClient *gophercloud.ServiceClient
	projectID     string
	vpcBaseURL    string

	// Cluster network CIDRs parsed as *net.IPNet
	clusterCIDRs []*net.IPNet

	// Metrics
	nodesProcessed *prometheus.CounterVec
	routeUpdates   *prometheus.CounterVec
	lastUpdate     *prometheus.GaugeVec
}

// NodeSubnetInfo holds the parsed subnet information from node annotation
type NodeSubnetInfo struct {
	Default string `json:"default"`
	IPv6    string `json:"ipv6,omitempty"`
}

// NodeSubnetInfoArrayFormat supports the array format of the annotation
type NodeSubnetInfoArrayFormat struct {
	Default []string `json:"default"`
	IPv6    []string `json:"ipv6,omitempty"`
}

// OTC Route Table structures
type RouteTable struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Routes []Route `json:"routes"`
	VPCID  string  `json:"vpc_id"`
}

type Route struct {
	Destination string `json:"destination"`
	Nexthop     string `json:"nexthop"`
	Type        string `json:"type"`
}

// OTC API update request format
type RouteTableUpdateRequest struct {
	Routetable RouteTableUpdate `json:"routetable"`
}

type RouteTableUpdate struct {
	Routes RouteUpdateOperations `json:"routes"`
}

type RouteUpdateOperations struct {
	Add []Route `json:"add,omitempty"`
	Mod []Route `json:"mod,omitempty"`
	Del []Route `json:"del,omitempty"`
}

// parseCIDRs parses a comma-separated list of CIDRs and returns a slice of *net.IPNet
func parseCIDRs(cidrs string) ([]*net.IPNet, error) {
	if cidrs == "" {
		return nil, nil
	}

	var networks []*net.IPNet
	for _, cidr := range strings.Split(cidrs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
		networks = append(networks, network)
	}

	return networks, nil
}

// isClusterTrafficRoute checks if a destination CIDR is part of cluster networks
func (rm *RouteManager) isClusterTrafficRoute(destinationCIDR string) bool {
	// Never touch the default route
	if destinationCIDR == "0.0.0.0/0" || destinationCIDR == "::/0" {
		log.Printf("Skipping default route: %s", destinationCIDR)
		return false
	}

	_, network, err := net.ParseCIDR(destinationCIDR)
	if err != nil {
		log.Printf("Warning: Invalid CIDR %s: %v", destinationCIDR, err)
		return false
	}

	for _, clusterNet := range rm.clusterCIDRs {
		if clusterNet.Contains(network.IP) && isSubnetContainedIn(network, clusterNet) {
			log.Printf("Route %s matches cluster CIDR %s", destinationCIDR, clusterNet.String())
			return true
		}
	}

	return false
}

// isSubnetContainedIn checks if subnet1 is completely contained within subnet2
func isSubnetContainedIn(subnet1, subnet2 *net.IPNet) bool {
	ones1, bits1 := subnet1.Mask.Size()
	ones2, bits2 := subnet2.Mask.Size()

	if bits1 != bits2 {
		return false
	}

	if ones1 < ones2 {
		return false
	}

	return subnet2.Contains(subnet1.IP)
}

// NewRouteManager creates a new RouteManager instance
func NewRouteManager(config *Config) (*RouteManager, error) {
	kubeClient, err := initKubernetesClient(config.KubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Kubernetes client: %w", err)
	}

	otcClient, computeClient, identityClient, projectID, vpcBaseURL, err := initOTCClients(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OTC clients: %w", err)
	}

	clusterCIDRs, err := parseCIDRs(config.ClusterCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster CIDRs: %w", err)
	}

	log.Printf("Managing routes for cluster CIDRs: %s", config.ClusterCIDR)

	nodesProcessed := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "route_manager_nodes_processed_total",
			Help: "Total number of nodes processed",
		},
		[]string{"status"},
	)

	routeUpdates := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "route_manager_updates_total",
			Help: "Total number of route updates",
		},
		[]string{"operation", "status"},
	)

	lastUpdate := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "route_manager_last_update_timestamp",
			Help: "Timestamp of last route update",
		},
		[]string{"node"},
	)

	prometheus.MustRegister(nodesProcessed)
	prometheus.MustRegister(routeUpdates)
	prometheus.MustRegister(lastUpdate)

	return &RouteManager{
		config:         config,
		kubeClient:     kubeClient,
		otcClient:      otcClient,
		computeClient:  computeClient,
		identityClient: identityClient,
		projectID:      projectID,
		vpcBaseURL:     vpcBaseURL,
		clusterCIDRs:   clusterCIDRs,
		nodesProcessed: nodesProcessed,
		routeUpdates:   routeUpdates,
		lastUpdate:     lastUpdate,
	}, nil
}

func initKubernetesClient(kubeConfigPath string) (kubernetes.Interface, error) {
	var config *rest.Config
	var err error

	if kubeConfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}

func getProjectIDByName(identityClient *gophercloud.ServiceClient, projectName string) (string, error) {
	client := &gophercloud.ServiceClient{
		ProviderClient: identityClient.ProviderClient,
		Endpoint:       identityClient.Endpoint,
	}

	listOpts := projects.ListOpts{
		Name: projectName,
	}

	allPages, err := projects.List(client, listOpts).AllPages()
	if err != nil {
		return "", fmt.Errorf("failed to list projects: %w", err)
	}

	allProjects, err := projects.ExtractProjects(allPages)
	if err != nil {
		return "", fmt.Errorf("failed to extract projects: %w", err)
	}

	if len(allProjects) == 0 {
		return "", fmt.Errorf("no project found with name %s", projectName)
	}

	if len(allProjects) > 1 {
		log.Printf("Warning: multiple projects found with name %s, using the first one", projectName)
	}

	return allProjects[0].ID, nil
}

func getOTCEndpoint(serviceType, region string) string {
	switch serviceType {
	case "identity":
		return fmt.Sprintf("https://iam.%s.otc.t-systems.com/v3/", region)
	case "network":
		return fmt.Sprintf("https://vpc.%s.otc.t-systems.com/v2.0/", region)
	case "compute":
		return fmt.Sprintf("https://ecs.%s.otc.t-systems.com/v2/", region)
	default:
		return ""
	}
}

func initOTCClients(config *Config) (*gophercloud.ServiceClient, *gophercloud.ServiceClient, *gophercloud.ServiceClient, string, string, error) {
	identityEndpoint := getOTCEndpoint("identity", config.Region)
	if identityEndpoint == "" {
		return nil, nil, nil, "", "", fmt.Errorf("failed to construct identity endpoint for region %s", config.Region)
	}

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         config.Username,
		Password:         config.Password,
		DomainName:       config.DomainName,
	}

	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return nil, nil, nil, "", "", fmt.Errorf("failed to authenticate with OTC: %w", err)
	}

	identityClient := &gophercloud.ServiceClient{
		ProviderClient: provider,
		Endpoint:       identityEndpoint,
	}

	projectID, err := getProjectIDByName(identityClient, config.ProjectName)
	if err != nil {
		return nil, nil, nil, "", "", fmt.Errorf("failed to get project ID: %w", err)
	}

	log.Printf("Found project ID: %s for project name: %s", projectID, config.ProjectName)

	projectOpts := gophercloud.AuthOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         config.Username,
		Password:         config.Password,
		DomainName:       config.DomainName,
		TenantID:         projectID,
	}

	projectProvider, err := openstack.AuthenticatedClient(projectOpts)
	if err != nil {
		return nil, nil, nil, "", "", fmt.Errorf("failed to authenticate with project scope: %w", err)
	}

	vpcEndpoint := getOTCEndpoint("network", config.Region)
	if vpcEndpoint == "" {
		return nil, nil, nil, "", "", fmt.Errorf("failed to construct VPC endpoint for region %s", config.Region)
	}

	vpcClient := &gophercloud.ServiceClient{
		ProviderClient: projectProvider,
		Endpoint:       vpcEndpoint,
	}

	vpcBaseURL := strings.Replace(vpcEndpoint, "v2.0/", "v1/", 1)
	log.Printf("VPC API base URL: %s", vpcBaseURL)

	computeEndpoint := getOTCEndpoint("compute", config.Region)
	if computeEndpoint == "" {
		return nil, nil, nil, "", "", fmt.Errorf("failed to construct compute endpoint for region %s", config.Region)
	}

	computeClient := &gophercloud.ServiceClient{
		ProviderClient: projectProvider,
		Endpoint:       computeEndpoint,
	}

	return vpcClient, computeClient, identityClient, projectID, vpcBaseURL, nil
}

func (rm *RouteManager) GetRouteTable() (*RouteTable, error) {
	if rm.config.RouteTableID == "" {
		return nil, fmt.Errorf("route table ID is required")
	}

	url := fmt.Sprintf("%s%s/routetables/%s", rm.vpcBaseURL, rm.projectID, rm.config.RouteTableID)
	log.Printf("Getting route table from URL: %s", url)

	var result gophercloud.Result
	_, err := rm.otcClient.Get(url, &result.Body, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get route table: %w", err)
	}

	var response struct {
		RouteTable RouteTable `json:"routetable"`
	}

	if err := result.ExtractInto(&response); err != nil {
		return nil, fmt.Errorf("failed to extract route table: %w", err)
	}

	return &response.RouteTable, nil
}

func (rm *RouteManager) UpdateRouteTable(operations RouteUpdateOperations) error {
	if rm.config.RouteTableID == "" {
		return fmt.Errorf("route table ID is required")
	}

	updateRequest := RouteTableUpdateRequest{
		Routetable: RouteTableUpdate{
			Routes: operations,
		},
	}

	url := fmt.Sprintf("%s%s/routetables/%s", rm.vpcBaseURL, rm.projectID, rm.config.RouteTableID)
	log.Printf("Updating route table at URL: %s", url)

	var result gophercloud.Result
	_, err := rm.otcClient.Put(url, updateRequest, &result.Body, &gophercloud.RequestOpts{
		JSONBody: updateRequest,
		OkCodes:  []int{200, 201, 202},
	})
	if err != nil {
		if len(operations.Add) > 0 {
			rm.routeUpdates.WithLabelValues("add", "error").Add(float64(len(operations.Add)))
		}
		if len(operations.Mod) > 0 {
			rm.routeUpdates.WithLabelValues("modify", "error").Add(float64(len(operations.Mod)))
		}
		if len(operations.Del) > 0 {
			rm.routeUpdates.WithLabelValues("delete", "error").Add(float64(len(operations.Del)))
		}
		return fmt.Errorf("failed to update route table: %w", err)
	}

	if len(operations.Add) > 0 {
		rm.routeUpdates.WithLabelValues("add", "success").Add(float64(len(operations.Add)))
	}
	if len(operations.Mod) > 0 {
		rm.routeUpdates.WithLabelValues("modify", "success").Add(float64(len(operations.Mod)))
	}
	if len(operations.Del) > 0 {
		rm.routeUpdates.WithLabelValues("delete", "success").Add(float64(len(operations.Del)))
	}

	var response struct {
		RouteTable RouteTable `json:"routetable"`
	}
	if err := result.ExtractInto(&response); err == nil {
		log.Printf("Route table updated successfully: %+v", response.RouteTable)
	}

	return nil
}

func (rm *RouteManager) GetNodeSubnetAnnotation(ctx context.Context, nodeName string) (*NodeSubnetInfo, error) {
	node, err := rm.kubeClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	annotation, exists := node.Annotations["k8s.ovn.org/node-subnets"]
	if !exists {
		return nil, fmt.Errorf("node %s does not have k8s.ovn.org/node-subnets annotation", nodeName)
	}

	log.Printf("Raw subnet annotation for node %s: %s", nodeName, annotation)

	var subnetInfo NodeSubnetInfo
	if err := json.Unmarshal([]byte(annotation), &subnetInfo); err == nil && subnetInfo.Default != "" {
		log.Printf("Parsed node subnet annotation (string format): %+v", subnetInfo)
		return &subnetInfo, nil
	}

	var arraySubnetInfo NodeSubnetInfoArrayFormat
	if err := json.Unmarshal([]byte(annotation), &arraySubnetInfo); err == nil {
		if len(arraySubnetInfo.Default) > 0 {
			subnetInfo.Default = arraySubnetInfo.Default[0]
			if len(arraySubnetInfo.IPv6) > 0 {
				subnetInfo.IPv6 = arraySubnetInfo.IPv6[0]
			}
			log.Printf("Parsed node subnet annotation (array format): %+v", subnetInfo)
			return &subnetInfo, nil
		}
	}

	return nil, fmt.Errorf("failed to parse subnet annotation: unsupported format or no default subnet found")
}

func (rm *RouteManager) GetNodeMachineID(ctx context.Context, nodeName string) (string, error) {
	node, err := rm.kubeClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	if node.Spec.ProviderID != "" {
		parts := strings.Split(node.Spec.ProviderID, "/")
		if len(parts) > 0 {
			instanceID := parts[len(parts)-1]
			if instanceID != "" {
				log.Printf("Found instance ID from provider ID: %s", instanceID)
				return instanceID, nil
			}
		}
	}

	return rm.findInstanceByNodeName(nodeName)
}

func (rm *RouteManager) findInstanceByNodeName(nodeName string) (string, error) {
	listOpts := servers.ListOpts{
		Name: nodeName,
	}

	allPages, err := servers.List(rm.computeClient, listOpts).AllPages()
	if err != nil {
		return "", fmt.Errorf("failed to list servers: %w", err)
	}

	allServers, err := servers.ExtractServers(allPages)
	if err != nil {
		return "", fmt.Errorf("failed to extract servers: %w", err)
	}

	if len(allServers) == 0 {
		return "", fmt.Errorf("no server found with name %s", nodeName)
	}

	if len(allServers) > 1 {
		log.Printf("Warning: multiple servers found with name %s, using the first one", nodeName)
	}

	log.Printf("Found server instance ID: %s", allServers[0].ID)
	return allServers[0].ID, nil
}

func (rm *RouteManager) CreateOrUpdateRoute(destinationCIDR, nextHop string) error {
	if !rm.isClusterTrafficRoute(destinationCIDR) {
		log.Printf("Skipping route %s: not cluster traffic", destinationCIDR)
		return nil
	}

	routeTable, err := rm.GetRouteTable()
	if err != nil {
		return fmt.Errorf("failed to get route table: %w", err)
	}

	var operations RouteUpdateOperations
	routeExists := false

	for _, route := range routeTable.Routes {
		if route.Destination == destinationCIDR {
			if route.Nexthop == nextHop {
				log.Printf("Route to %s via %s already exists", destinationCIDR, nextHop)
				return nil
			}
			routeExists = true
			break
		}
	}

	if routeExists {
		operations.Mod = []Route{
			{
				Destination: destinationCIDR,
				Nexthop:     nextHop,
				Type:        "ecs",
			},
		}
		log.Printf("Modifying cluster route: destination=%s, nextHop=%s, type=ecs", destinationCIDR, nextHop)
	} else {
		operations.Add = []Route{
			{
				Destination: destinationCIDR,
				Nexthop:     nextHop,
				Type:        "ecs",
			},
		}
		log.Printf("Adding new cluster route: destination=%s, nextHop=%s, type=ecs", destinationCIDR, nextHop)
	}

	err = rm.UpdateRouteTable(operations)
	if err != nil {
		return fmt.Errorf("failed to update route table: %w", err)
	}

	return nil
}

func (rm *RouteManager) ProcessNode(ctx context.Context, nodeName string) error {
	log.Printf("Processing node: %s", nodeName)

	subnetInfo, err := rm.GetNodeSubnetAnnotation(ctx, nodeName)
	if err != nil {
		rm.nodesProcessed.WithLabelValues("error").Inc()
		return fmt.Errorf("failed to get subnet annotation: %w", err)
	}

	if !rm.isClusterTrafficRoute(subnetInfo.Default) {
		log.Printf("Skipping node %s: subnet %s is not cluster traffic", nodeName, subnetInfo.Default)
		rm.nodesProcessed.WithLabelValues("skipped").Inc()
		return nil
	}

	instanceID, err := rm.GetNodeMachineID(ctx, nodeName)
	if err != nil {
		rm.nodesProcessed.WithLabelValues("error").Inc()
		return fmt.Errorf("failed to get instance ID: %w", err)
	}

	err = rm.CreateOrUpdateRoute(subnetInfo.Default, instanceID)
	if err != nil {
		rm.nodesProcessed.WithLabelValues("error").Inc()
		return fmt.Errorf("failed to create/update route: %w", err)
	}

	rm.nodesProcessed.WithLabelValues("success").Inc()
	rm.lastUpdate.WithLabelValues(nodeName).SetToCurrentTime()
	log.Printf("Successfully processed node %s", nodeName)
	return nil
}

func (rm *RouteManager) ProcessAllNodes(ctx context.Context) error {
	nodes, err := rm.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	for _, node := range nodes.Items {
		if !isWorkerNode(node) {
			log.Printf("Skipping master/control-plane node: %s", node.Name)
			continue
		}

		if err := rm.ProcessNode(ctx, node.Name); err != nil {
			log.Printf("Error processing node %s: %v", node.Name, err)
			continue
		}
	}

	return nil
}

func (rm *RouteManager) CleanupStaleRoutes(ctx context.Context) error {
	nodes, err := rm.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	routeTable, err := rm.GetRouteTable()
	if err != nil {
		return err
	}

	activeSubnets := make(map[string]bool)
	for _, node := range nodes.Items {
		if !isWorkerNode(node) {
			continue
		}

		subnetInfo, err := rm.GetNodeSubnetAnnotation(ctx, node.Name)
		if err != nil {
			log.Printf("Warning: Failed to get subnet for node %s: %v", node.Name, err)
			continue
		}

		if rm.isClusterTrafficRoute(subnetInfo.Default) {
			activeSubnets[subnetInfo.Default] = true
		}
	}

	var routesToDelete []Route
	for _, route := range routeTable.Routes {
		if rm.isClusterTrafficRoute(route.Destination) && !activeSubnets[route.Destination] {
			routesToDelete = append(routesToDelete, route)
			log.Printf("Marking stale cluster route for deletion: CIDR=%s", route.Destination)
		}
	}

	if len(routesToDelete) > 0 {
		operations := RouteUpdateOperations{
			Del: routesToDelete,
		}
		err = rm.UpdateRouteTable(operations)
		if err != nil {
			return err
		}
		log.Printf("Cleaned up %d stale cluster routes", len(routesToDelete))
	} else {
		log.Printf("No stale cluster routes found")
	}

	return nil
}

func (rm *RouteManager) WatchNodes(ctx context.Context) error {
	watcher, err := rm.kubeClient.CoreV1().Nodes().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to create node watcher: %w", err)
	}
	defer watcher.Stop()

	ch := watcher.ResultChan()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-ch:
			if !ok {
				return fmt.Errorf("watch channel closed")
			}

			node, ok := event.Object.(*corev1.Node)
			if !ok {
				continue
			}

			if !isWorkerNode(*node) {
				continue
			}

			switch event.Type {
			case watch.Added, watch.Modified:
				log.Printf("Node %s added/modified", node.Name)
				if err := rm.ProcessNode(ctx, node.Name); err != nil {
					log.Printf("Error processing node %s: %v", node.Name, err)
				}
			case watch.Deleted:
				log.Printf("Node %s deleted", node.Name)
				if err := rm.CleanupStaleRoutes(ctx); err != nil {
					log.Printf("Error cleaning up stale routes: %v", err)
				}
			}
		}
	}
}

func isWorkerNode(node corev1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if taint.Key == "node-role.kubernetes.io/master" ||
			taint.Key == "node-role.kubernetes.io/control-plane" {
			return false
		}
	}

	if role, exists := node.Labels["node-role.kubernetes.io/master"]; exists && role == "true" {
		return false
	}
	if role, exists := node.Labels["node-role.kubernetes.io/control-plane"]; exists && role == "true" {
		return false
	}

	return true
}

func (rm *RouteManager) runDaemonsetMode(ctx context.Context) error {
	nodeName := rm.config.NodeName
	if nodeName == "" {
		return fmt.Errorf("NODE_NAME is required for daemonset mode")
	}

	log.Printf("Starting daemonset mode for node %s with update interval %v", nodeName, rm.config.UpdateInterval)

	log.Printf("Performing initial route update for node %s", nodeName)
	if err := rm.ProcessNode(ctx, nodeName); err != nil {
		log.Printf("Initial route update failed for node %s: %v", nodeName, err)
	}

	ticker := time.NewTicker(rm.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Context cancelled, stopping daemonset mode")
			return ctx.Err()
		case <-ticker.C:
			log.Printf("Periodic route update for node %s", nodeName)
			if err := rm.ProcessNode(ctx, nodeName); err != nil {
				log.Printf("Periodic route update failed for node %s: %v", nodeName, err)
			} else {
				log.Printf("Successfully updated route for node %s", nodeName)
			}
		}
	}
}

func (rm *RouteManager) StartMetricsServer() {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	port := rm.config.MetricsPort
	if port == "" {
		port = "8080"
	}

	go func() {
		log.Printf("Starting metrics server on :%s", port)
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			log.Printf("Metrics server error: %v", err)
		}
	}()
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadConfigFromEnv() *Config {
	config := &Config{
		KubeConfigPath:   os.Getenv("KUBECONFIG"),
		NodeName:         os.Getenv("NODE_NAME"),
		IdentityEndpoint: getEnvOrDefault("OS_AUTH_URL", "https://iam.eu-de.otc.t-systems.com/v3"),
		Username:         os.Getenv("OS_USERNAME"),
		Password:         os.Getenv("OS_PASSWORD"),
		DomainName:       getEnvOrDefault("OS_DOMAIN_NAME", "OTC00000000001000000xxx"),
		ProjectName:      os.Getenv("OS_PROJECT_NAME"),
		Region:           getEnvOrDefault("OS_REGION_NAME", "eu-de"),
		RouteTableID:     os.Getenv("ROUTE_TABLE_ID"),
		MetricsPort:      getEnvOrDefault("METRICS_PORT", "8080"),
		ClusterCIDR:      getEnvOrDefault("CLUSTER_CIDR", "192.168.0.0/16"),
	}

	config.IsDaemonset = config.NodeName != ""

	intervalStr := getEnvOrDefault("UPDATE_INTERVAL", "60")
	intervalSeconds, err := strconv.Atoi(intervalStr)
	if err != nil {
		log.Printf("Warning: invalid UPDATE_INTERVAL value %s, using default 60s", intervalStr)
		intervalSeconds = 60
	}
	config.UpdateInterval = time.Duration(intervalSeconds) * time.Second

	return config
}

func validateConfig(config *Config) error {
	required := map[string]string{
		"OS_USERNAME":     config.Username,
		"OS_PASSWORD":     config.Password,
		"OS_PROJECT_NAME": config.ProjectName,
		"ROUTE_TABLE_ID":  config.RouteTableID,
	}

	for name, value := range required {
		if value == "" {
			return fmt.Errorf("missing required configuration: %s", name)
		}
	}

	if config.ClusterCIDR == "" {
		return fmt.Errorf("CLUSTER_CIDR must be provided")
	}

	if config.IsDaemonset && config.UpdateInterval < time.Second {
		return fmt.Errorf("UPDATE_INTERVAL must be at least 1 second")
	}

	return nil
}

func main() {
	log.Println("Starting OTC Kubernetes Route Manager (Cluster Traffic Only)")

	config := loadConfigFromEnv()

	if err := validateConfig(config); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	routeManager, err := NewRouteManager(config)
	if err != nil {
		log.Fatalf("Failed to create route manager: %v", err)
	}

	routeManager.StartMetricsServer()

	ctx := context.Background()

	if config.IsDaemonset {
		log.Printf("Running in daemonset mode for node: %s", config.NodeName)
		if err := routeManager.runDaemonsetMode(ctx); err != nil {
			log.Fatalf("Daemonset mode failed: %v", err)
		}
	} else {
		if err := routeManager.CleanupStaleRoutes(ctx); err != nil {
			log.Printf("Warning: Failed to cleanup stale routes: %v", err)
		}

		log.Println("Running in traditional mode (managing all worker nodes)")
		log.Println("Processing all worker nodes initially...")
		if err := routeManager.ProcessAllNodes(ctx); err != nil {
			log.Printf("Error during initial processing: %v", err)
		}

		log.Println("Starting node watcher...")
		if err := routeManager.WatchNodes(ctx); err != nil {
			log.Fatalf("Node watcher failed: %v", err)
		}
	}
}