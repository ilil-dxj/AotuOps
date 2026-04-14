package main

import (
	"flag"
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"k8s-admin/internal/api/handlers"
)

func main() {
	kubeconfig := flag.String("kubeconfig", os.Getenv("HOME")+"/.kube/config", "path to kubeconfig")
	addr := flag.String("addr", ":8080", "server address")
	flag.Parse()

	// Initialize default cluster
	if err := handlers.InitDefaultCluster(*kubeconfig); err != nil {
		log.Printf("Warning: Failed to connect to default cluster: %v", err)
	}

	r := gin.Default()

	h := handlers.NewHandler()

	// Dashboard
	r.GET("/", h.Dashboard)

	// Auth
	api := r.Group("/api/v1")
	{
		// Auth (no auth required)
		api.POST("/auth/login", h.Login)
		api.POST("/auth/logout", h.Logout)

		// Cluster management
		api.POST("/clusters/connect", h.ConnectCluster)
		api.GET("/clusters", h.GetClusters)
		api.POST("/clusters/switch", h.SwitchCluster)

		// Cluster info
		api.GET("/cluster", h.GetClusterInfo)

		// Metrics
		api.GET("/metrics/nodes", h.GetNodeMetrics)
		api.GET("/metrics/pods", h.GetPodMetrics)

		// YAML validation
		api.POST("/validate/yaml", h.ValidateYAML)

		// Namespaces
		api.GET("/namespaces", h.ListNamespaces)
		api.GET("/namespaces/:namespace/events", h.ListEvents)

		// Nodes
		api.GET("/nodes", h.ListNodes)
		api.GET("/nodes/:node", h.GetNode)

		// Pods
		api.GET("/pods", h.ListPods)
		api.GET("/namespaces/:namespace/pods", h.ListPods)
		api.GET("/namespaces/:namespace/pods/:name", h.GetPod)
		api.GET("/namespaces/:namespace/pods/:name/log", h.GetPodLog)

		// Deployments
		api.GET("/deployments", h.ListDeployments)
		api.GET("/namespaces/:namespace/deployments", h.ListDeployments)
		api.GET("/namespaces/:namespace/deployments/:name", h.GetDeployment)
		api.POST("/namespaces/:namespace/deployments", h.CreateDeployment)
		api.PUT("/namespaces/:namespace/deployments/:name", h.UpdateDeployment)
		api.DELETE("/namespaces/:namespace/deployments/:name", h.DeleteDeployment)
		api.POST("/namespaces/:namespace/deployments/:name/scale", h.ScaleDeployment)

		// StatefulSets
		api.GET("/statefulsets", h.ListStatefulSets)
		api.GET("/namespaces/:namespace/statefulsets", h.ListStatefulSets)
		api.GET("/namespaces/:namespace/statefulsets/:name", h.GetStatefulSet)

		// DaemonSets
		api.GET("/daemonsets", h.ListDaemonSets)
		api.GET("/namespaces/:namespace/daemonsets", h.ListDaemonSets)
		api.GET("/namespaces/:namespace/daemonsets/:name", h.GetDaemonSet)

		// Services
		api.GET("/services", h.ListServices)
		api.GET("/namespaces/:namespace/services", h.ListServices)
		api.GET("/namespaces/:namespace/services/:name", h.GetService)
		api.POST("/namespaces/:namespace/services", h.CreateService)
		api.PUT("/namespaces/:namespace/services/:name", h.UpdateService)
		api.DELETE("/namespaces/:namespace/services/:name", h.DeleteService)

		// Ingresses
		api.GET("/ingresses", h.ListIngresses)
		api.GET("/namespaces/:namespace/ingresses", h.ListIngresses)
		api.GET("/namespaces/:namespace/ingresses/:name", h.GetIngress)
		api.POST("/namespaces/:namespace/ingresses", h.CreateIngress)
		api.PUT("/namespaces/:namespace/ingresses/:name", h.UpdateIngress)
		api.DELETE("/namespaces/:namespace/ingresses/:name", h.DeleteIngress)

		// ConfigMaps
		api.GET("/configmaps", h.ListConfigMaps)
		api.GET("/namespaces/:namespace/configmaps", h.ListConfigMaps)
		api.GET("/namespaces/:namespace/configmaps/:name", h.GetConfigMap)
		api.POST("/namespaces/:namespace/configmaps", h.CreateConfigMap)
		api.PUT("/namespaces/:namespace/configmaps/:name", h.UpdateConfigMap)
		api.DELETE("/namespaces/:namespace/configmaps/:name", h.DeleteConfigMap)

		// Secrets
		api.GET("/secrets", h.ListSecrets)
		api.GET("/namespaces/:namespace/secrets", h.ListSecrets)
		api.GET("/namespaces/:namespace/secrets/:name", h.GetSecret)
		api.POST("/namespaces/:namespace/secrets", h.CreateSecret)
		api.DELETE("/namespaces/:namespace/secrets/:name", h.DeleteSecret)

		// PVCs
		api.GET("/pvcs", h.ListPVCs)
		api.GET("/namespaces/:namespace/pvcs", h.ListPVCs)
		api.GET("/namespaces/:namespace/pvcs/:name", h.GetPVC)

		// Jobs
		api.GET("/jobs", h.ListJobs)
		api.GET("/namespaces/:namespace/jobs", h.ListJobs)
		api.GET("/namespaces/:namespace/jobs/:name", h.GetJob)

		// CronJobs
		api.GET("/cronjobs", h.ListCronJobs)
		api.GET("/namespaces/:namespace/cronjobs", h.ListCronJobs)
		api.GET("/namespaces/:namespace/cronjobs/:name", h.GetCronJob)
		api.POST("/namespaces/:namespace/cronjobs", h.CreateCronJob)
		api.PUT("/namespaces/:namespace/cronjobs/:name", h.UpdateCronJob)
		api.DELETE("/namespaces/:namespace/cronjobs/:name", h.DeleteCronJob)

		// WebSocket Terminal
		api.GET("/ws/terminal", h.WebSocketTerminal)
		
		// Host Management
		api.GET("/hosts", h.GetHosts)
		api.POST("/hosts", h.CreateHost)
		api.DELETE("/hosts/:id", h.DeleteHost)
		api.GET("/hosts/:id/ping", h.PingHost)
		api.GET("/hosts/:id/metrics", h.GetHostMetrics)
		api.POST("/hosts/:id/collect", h.CollectHostMetrics)
		api.POST("/hosts/ssh", h.SSHTerminal)
		
		// Host Groups
		api.GET("/host-groups", h.GetHostGroups)
		api.POST("/host-groups", h.CreateHostGroup)
		api.DELETE("/host-groups/:id", h.DeleteHostGroup)
		
		// MySQL
		api.GET("/mysql", h.GetMySQLConnections)
		api.POST("/mysql", h.CreateMySQLConnection)
		api.DELETE("/mysql/:id", h.DeleteMySQLConnection)
		api.GET("/mysql/:id/test", h.TestMySQLConnection)
		api.POST("/mysql/:id/query", h.QueryMySQL)
		
		// Redis
		api.GET("/redis", h.GetRedisConnections)
		api.POST("/redis", h.CreateRedisConnection)
		api.DELETE("/redis/:id", h.DeleteRedisConnection)
		api.GET("/redis/:id/test", h.TestRedisConnection)
		api.POST("/redis/:id/query", h.QueryRedis)
		
		// Operation Logs
		api.GET("/logs", h.GetOperationLogs)
	}

	log.Printf("K8s Admin starting on %s", *addr)
	if err := r.Run(*addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
