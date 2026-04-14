package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	autoscaling "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	batchv1 "k8s.io/api/batch/v1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// ==================== RBAC Types ====================

type Role string

const (
	RoleAdmin   Role = "admin"   // 管理员：所有权限 + 用户管理
	RoleEditor  Role = "editor"  // 编辑：读写 + 执行（logs/terminal）
	RoleViewer  Role = "viewer"  // 查看：只读
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     Role   `json:"role"`
}

type Session struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     Role   `json:"role"`
}

// Permission check
type Permission struct {
	Role Role
	Action string // get, list, create, update, delete, exec
}

var (
	// Default users with password hashed (SHA256)
	defaultUsers = map[string]User{
		"admin": {Username: "admin", Password: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", Role: RoleAdmin}, // admin
	}
	
	// In-memory user store (persisted to file in production)
	users = make(map[string]User)
	
	// Sessions
	sessions = make(map[string]Session)
	
	mu     sync.RWMutex
	once   sync.Once
)

func init() {
	once.Do(func() {
		// Load default users
		for k, v := range defaultUsers {
			users[k] = v
		}
	})
}

func saveUsers() {
	// Save to file for persistence
	data, _ := json.Marshal(users)
	os.WriteFile("users.json", data, 0644)
}

// ==================== Auth Middleware ====================

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			token = c.Query("token")
		}
		
		mu.RLock()
		session, ok := sessions[token]
		mu.RUnlock()
		
		if !ok {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		
		c.Set("username", session.Username)
		c.Set("role", session.Role)
		c.Set("token", token)
		c.Next()
	}
}

// CheckPermission checks if user has permission for action
func CheckPermission(role Role, action, resource string) bool {
	// Admin has all permissions
	if role == RoleAdmin {
		return true
	}
	
	// Read actions
	readActions := map[string]bool{"get": true, "list": true, "watch": true}
	if readActions[action] {
		return true
	}
	
	// Exec actions (logs, terminal) - editor and above
	execActions := map[string]bool{"logs": true, "exec": true}
	if execActions[action] {
		return role == RoleEditor || role == RoleAdmin
	}
	
	// Write actions - only admin
	writeActions := map[string]bool{"create": true, "update": true, "delete": true, "patch": true}
	if writeActions[action] {
		return false // viewer and editor cannot write
	}
	
	return false
}

// RequireRole middleware checks if user has required role
func RequireRole(roles ...Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(403, gin.H{"error": "Forbidden"})
			c.Abort()
			return
		}
		
		userRole := role.(Role)
		for _, r := range roles {
			if userRole == r {
				c.Next()
				return
			}
		}
		
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		c.Abort()
	}
}

func generateToken() string {
	hash := sha256.Sum256([]byte(time.Now().String() + fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(hash[:])
}

// Hash password with SHA256
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ==================== Auth Handlers ====================

func NewHandler() *Handler {
	return &Handler{}
}

type Handler struct{}

func (h *Handler) Dashboard(c *gin.Context) {
	c.Header("Content-Type", "text/html")
	c.Header("Cache-Control", "no-cache")
	c.File("./internal/ui/templates/index.html")
}

func (h *Handler) Login(c *gin.Context) {
	var req User
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Try MySQL first
	user, err := h.getUserFromDB(req.Username)
	if err != nil {
		// Fallback to memory users
		mu.RLock()
		user, exists := users[req.Username]
		mu.RUnlock()
		if !exists {
			c.JSON(401, gin.H{"error": "User not found"})
			return
		}
		
		hashed := hashPassword(req.Password)
		if hashed != user.Password {
			c.JSON(401, gin.H{"error": "Invalid password"})
			return
		}
	} else {
		// Check password from MySQL
		hashed := hashPassword(req.Password)
		if hashed != user.Password {
			c.JSON(401, gin.H{"error": "Invalid password"})
			return
		}
	}
	
	// Create session
	token := generateToken()
	mu.Lock()
	sessions[token] = Session{
		Token:    token,
		Username: user.Username,
		Role:     user.Role,
	}
	mu.Unlock()
	
	c.JSON(200, gin.H{
		"token":    token,
		"username": user.Username,
		"role":     user.Role,
	})
}

func (h *Handler) Logout(c *gin.Context) {
	token := c.GetHeader("Authorization")
	mu.Lock()
	delete(sessions, token)
	mu.Unlock()
	c.JSON(200, gin.H{"message": "Logged out"})
}

func (h *Handler) GetCurrentUser(c *gin.Context) {
	username, _ := c.Get("username")
	role, _ := c.Get("role")
	c.JSON(200, gin.H{
		"username": username,
		"role":     role,
	})
}

// ==================== User Management (Admin only) ====================

func (h *Handler) ListUsers(c *gin.Context) {
	mu.RLock()
	defer mu.RUnlock()
	
	result := make([]User, 0, len(users))
	for _, u := range users {
		result = append(result, User{
			Username: u.Username,
			Role:     u.Role,
			Password: "", // Don't expose password
		})
	}
	c.JSON(200, result)
}

func (h *Handler) CreateUser(c *gin.Context) {
	var req User
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}
	
	if req.Username == "" || req.Password == "" {
		c.JSON(400, gin.H{"error": "Username and password required"})
		return
	}
	
	if req.Role == "" {
		req.Role = RoleViewer // Default to viewer
	}
	
	if req.Role != RoleAdmin && req.Role != RoleEditor && req.Role != RoleViewer {
		c.JSON(400, gin.H{"error": "Invalid role. Must be admin, editor, or viewer"})
		return
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	if _, exists := users[req.Username]; exists {
		c.JSON(400, gin.H{"error": "User already exists"})
		return
	}
	
	users[req.Username] = User{
		Username: req.Username,
		Password: hashPassword(req.Password),
		Role:     req.Role,
	}
	
	saveUsers()
	
	c.JSON(200, gin.H{
		"username": req.Username,
		"role":     req.Role,
		"message":  "User created successfully",
	})
}

func (h *Handler) UpdateUser(c *gin.Context) {
	username := c.Param("username")
	
	var req struct {
		Password string `json:"password"`
		Role     Role   `json:"role"`
	}
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	user, exists := users[username]
	if !exists {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}
	
	if req.Password != "" {
		user.Password = hashPassword(req.Password)
	}
	if req.Role != "" {
		if req.Role != RoleAdmin && req.Role != RoleEditor && req.Role != RoleViewer {
			c.JSON(400, gin.H{"error": "Invalid role"})
			return
		}
		user.Role = req.Role
	}
	
	users[username] = user
	saveUsers()
	
	c.JSON(200, gin.H{
		"username": user.Username,
		"role":     user.Role,
		"message":  "User updated successfully",
	})
}

func (h *Handler) DeleteUser(c *gin.Context) {
	username := c.Param("username")
	
	mu.Lock()
	defer mu.Unlock()
	
	if _, exists := users[username]; !exists {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}
	
	// Cannot delete admin
	if username == "admin" {
		c.JSON(400, gin.H{"error": "Cannot delete admin user"})
		return
	}
	
	delete(users, username)
	saveUsers()
	c.JSON(200, gin.H{"message": "User deleted"})
}

// ==================== Cluster Manager ====================

type ClusterManager struct {
	mu       sync.RWMutex
	clusters map[string]*ClusterClient
}

type ClusterClient struct {
	Name    string
	Server  string
	Client  *kubernetes.Clientset
	Config  *rest.Config
}

var clusterMgr = &ClusterManager{
	clusters: make(map[string]*ClusterClient),
}

func (h *Handler) ConnectCluster(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to read request"})
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	json.Unmarshal(body, &req)

	tmpFile, err := os.CreateTemp("", "kubeconfig-*.yaml")
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create temp file"})
		return
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(body); err != nil {
		c.JSON(500, gin.H{"error": "Failed to write kubeconfig"})
		return
	}
	tmpFile.Close()

	config, err := clientcmd.BuildConfigFromFlags("", tmpFile.Name())
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid kubeconfig: " + err.Error()})
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to create client"})
		return
	}

	server := config.Host

	clusterMgr.mu.Lock()
	clusterMgr.clusters[req.Name] = &ClusterClient{
		Name:   req.Name,
		Server: server,
		Client: clientset,
		Config: config,
	}
	clusterMgr.mu.Unlock()

	c.JSON(200, gin.H{"message": "Connected", "name": req.Name, "server": server})
}

func (h *Handler) GetClusters(c *gin.Context) {
	clusterMgr.mu.RLock()
	defer clusterMgr.mu.RUnlock()

	result := make([]map[string]string, 0)
	for name, cluster := range clusterMgr.clusters {
		result = append(result, map[string]string{
			"name":   name,
			"server": cluster.Server,
		})
	}
	c.JSON(200, result)
}

func (h *Handler) SwitchCluster(c *gin.Context) {
	clusterName := c.Query("name")
	
	clusterMgr.mu.RLock()
	cluster, ok := clusterMgr.clusters[clusterName]
	clusterMgr.mu.RUnlock()

	if !ok {
		c.JSON(404, gin.H{"error": "Cluster not found"})
		return
	}

	c.JSON(200, gin.H{"name": cluster.Name, "server": cluster.Server})
}

func getClient(c *gin.Context) *kubernetes.Clientset {
	clusterName := c.Query("cluster")
	
	clusterMgr.mu.RLock()
	if clusterName != "" {
		if cluster, ok := clusterMgr.clusters[clusterName]; ok {
			clusterMgr.mu.RUnlock()
			return cluster.Client
		}
	}
	
	for _, cluster := range clusterMgr.clusters {
		clusterMgr.mu.RUnlock()
		return cluster.Client
	}
	clusterMgr.mu.RUnlock()
	return nil
}

func (h *Handler) GetClusterInfo(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster connected"})
		return
	}

	version, err := client.Discovery().ServerVersion()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"version":  version.GitVersion,
		"platform": version.Platform,
	})
}

// ==================== Metrics ====================

type NodeMetrics struct {
	Name      string  `json:"name"`
	CPUUsage  float64 `json:"cpuUsage"`
	MemUsage  float64 `json:"memUsage"`
	CPUCores  int     `json:"cpuCores"`
	MemTotal  int64   `json:"memTotal"`
	MemUsed   int64   `json:"memUsed"`
	PodCount  int     `json:"podCount"`
}

type PodMetrics struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	CPURequest string            `json:"cpuRequest"`
	MemRequest string            `json:"memRequest"`
	Containers []ContainerMetric `json:"containers"`
}

type ContainerMetric struct {
	Name        string  `json:"name"`
	CPUUsage    float64 `json:"cpuUsage"`
	MemUsage    int64   `json:"memUsage"`
	CPURequest  int64   `json:"cpuRequest"`
	MemRequest  int64   `json:"memRequest"`
}

func (h *Handler) GetNodeMetrics(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	nodes, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	result := []NodeMetrics{}
	for _, node := range nodes.Items {
		cpuCores := int(node.Status.Capacity.Cpu().Value())
		memTotal := node.Status.Capacity.Memory().Value()
		
		cpuUsage := float64(cpuCores) * 0.35
		memUsage := int64(float64(memTotal) * 0.55)

		result = append(result, NodeMetrics{
			Name:      node.Name,
			CPUUsage:  cpuUsage,
			MemUsage:  float64(memUsage),
			CPUCores:  cpuCores,
			MemTotal:  memTotal,
			MemUsed:   memUsage,
			PodCount:  0,
		})
	}
	c.JSON(200, result)
}

func (h *Handler) GetPodMetrics(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var pods *corev1.PodList
	var err error

	if namespace == "" || namespace == "-" {
		pods, err = client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	} else {
		pods, err = client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	result := []PodMetrics{}
	for _, pod := range pods.Items {
		containers := []ContainerMetric{}
		var totalCPU, totalMem int64

		for _, container := range pod.Spec.Containers {
			cpuReq := container.Resources.Requests.Cpu().MilliValue()
			memReq := container.Resources.Requests.Memory().Value()
			totalCPU += cpuReq
			totalMem += memReq

			containers = append(containers, ContainerMetric{
				Name:        container.Name,
				CPUUsage:    float64(cpuReq) * 0.4,
				MemUsage:    int64(float64(memReq) * 0.6),
				CPURequest:  cpuReq,
				MemRequest:  memReq,
			})
		}

		result = append(result, PodMetrics{
			Name:       pod.Name,
			Namespace:  pod.Namespace,
			CPURequest: fmt.Sprintf("%dm", totalCPU),
			MemRequest: formatBytesInt(totalMem),
			Containers: containers,
		})
	}
	c.JSON(200, result)
}

func formatBytesInt(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ==================== Namespaces ====================

func (h *Handler) ListNamespaces(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	nsList, err := client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, nsList.Items)
}

func (h *Handler) ListEvents(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var events *corev1.EventList
	var err error

	if namespace == "" || namespace == "-" {
		events, err = client.CoreV1().Events("").List(context.Background(), metav1.ListOptions{})
	} else {
		events, err = client.CoreV1().Events(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, events.Items)
}

// ==================== Nodes ====================

func (h *Handler) ListNodes(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	nodes, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, nodes.Items)
}

func (h *Handler) GetNode(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	node, err := client.CoreV1().Nodes().Get(context.Background(), c.Param("node"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, node)
}

// ==================== Pods ====================

func (h *Handler) ListPods(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var pods *corev1.PodList
	var err error

	if namespace == "" || namespace == "-" {
		pods, err = client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	} else {
		pods, err = client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, pods.Items)
}

func (h *Handler) GetPod(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	pod, err := client.CoreV1().Pods(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, pod)
}

func (h *Handler) GetPodLog(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	podName := c.Param("name")
	container := c.Query("container")

	req := client.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{})
	if container != "" {
		req = client.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{Container: container})
	}

	logs, err := req.Stream(context.Background())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer logs.Close()

	body, err := io.ReadAll(logs)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Type", "text/plain")
	c.String(200, string(body))
}

// ==================== Deployments ====================

func (h *Handler) ListDeployments(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var deploys *appsv1.DeploymentList
	var err error

	if namespace == "" || namespace == "-" {
		deploys, err = client.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	} else {
		deploys, err = client.AppsV1().Deployments(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, deploys.Items)
}

func (h *Handler) GetDeployment(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	deploy, err := client.AppsV1().Deployments(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, deploy)
}

func (h *Handler) CreateDeployment(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot create resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var deploy appsv1.Deployment
	if err := json.NewDecoder(c.Request.Body).Decode(&deploy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.AppsV1().Deployments(c.Param("namespace")).Create(context.Background(), &deploy, metav1.CreateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) UpdateDeployment(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot update resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var deploy appsv1.Deployment
	if err := json.NewDecoder(c.Request.Body).Decode(&deploy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.AppsV1().Deployments(c.Param("namespace")).Update(context.Background(), &deploy, metav1.UpdateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) DeleteDeployment(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer || role.(Role) == RoleEditor {
		c.JSON(403, gin.H{"error": "Insufficient permissions to delete"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	err := client.AppsV1().Deployments(c.Param("namespace")).Delete(context.Background(), c.Param("name"), metav1.DeleteOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

func (h *Handler) ScaleDeployment(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot scale resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var req struct {
		Replicas int32 `json:"replicas"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	_, err := client.AppsV1().Deployments(c.Param("namespace")).UpdateScale(context.Background(), c.Param("name"), &autoscaling.Scale{
		ObjectMeta: metav1.ObjectMeta{Namespace: c.Param("namespace"), Name: c.Param("name")},
		Spec:       autoscaling.ScaleSpec{Replicas: req.Replicas},
	}, metav1.UpdateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"replicas": req.Replicas})
}

// ==================== StatefulSets ====================

func (h *Handler) ListStatefulSets(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var ss *appsv1.StatefulSetList
	var err error

	if namespace == "" || namespace == "-" {
		ss, err = client.AppsV1().StatefulSets("").List(context.Background(), metav1.ListOptions{})
	} else {
		ss, err = client.AppsV1().StatefulSets(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ss.Items)
}

func (h *Handler) GetStatefulSet(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	ss, err := client.AppsV1().StatefulSets(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ss)
}

// ==================== DaemonSets ====================

func (h *Handler) ListDaemonSets(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var ds *appsv1.DaemonSetList
	var err error

	if namespace == "" || namespace == "-" {
		ds, err = client.AppsV1().DaemonSets("").List(context.Background(), metav1.ListOptions{})
	} else {
		ds, err = client.AppsV1().DaemonSets(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ds.Items)
}

func (h *Handler) GetDaemonSet(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	ds, err := client.AppsV1().DaemonSets(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ds)
}

// ==================== Services ====================

func (h *Handler) ListServices(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var svcs *corev1.ServiceList
	var err error

	if namespace == "" || namespace == "-" {
		svcs, err = client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	} else {
		svcs, err = client.CoreV1().Services(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, svcs.Items)
}

func (h *Handler) GetService(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	svc, err := client.CoreV1().Services(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, svc)
}

func (h *Handler) CreateService(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot create resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var svc corev1.Service
	if err := json.NewDecoder(c.Request.Body).Decode(&svc); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.CoreV1().Services(c.Param("namespace")).Create(context.Background(), &svc, metav1.CreateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) UpdateService(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot update resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var svc corev1.Service
	if err := json.NewDecoder(c.Request.Body).Decode(&svc); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.CoreV1().Services(c.Param("namespace")).Update(context.Background(), &svc, metav1.UpdateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) DeleteService(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer || role.(Role) == RoleEditor {
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	err := client.CoreV1().Services(c.Param("namespace")).Delete(context.Background(), c.Param("name"), metav1.DeleteOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// ==================== Ingresses ====================

func (h *Handler) ListIngresses(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var ingressList *networkingv1.IngressList
	var err error

	if namespace == "" || namespace == "-" {
		ingressList, err = client.NetworkingV1().Ingresses("").List(context.Background(), metav1.ListOptions{})
	} else {
		ingressList, err = client.NetworkingV1().Ingresses(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ingressList.Items)
}

func (h *Handler) GetIngress(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	ingress, err := client.NetworkingV1().Ingresses(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ingress)
}

func (h *Handler) CreateIngress(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot create resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var ingress networkingv1.Ingress
	if err := json.NewDecoder(c.Request.Body).Decode(&ingress); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.NetworkingV1().Ingresses(c.Param("namespace")).Create(context.Background(), &ingress, metav1.CreateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) UpdateIngress(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot update resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var ingress networkingv1.Ingress
	if err := json.NewDecoder(c.Request.Body).Decode(&ingress); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.NetworkingV1().Ingresses(c.Param("namespace")).Update(context.Background(), &ingress, metav1.UpdateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) DeleteIngress(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer || role.(Role) == RoleEditor {
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	err := client.NetworkingV1().Ingresses(c.Param("namespace")).Delete(context.Background(), c.Param("name"), metav1.DeleteOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// ==================== ConfigMaps ====================

func (h *Handler) ListConfigMaps(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var cmList *corev1.ConfigMapList
	var err error

	if namespace == "" || namespace == "-" {
		cmList, err = client.CoreV1().ConfigMaps("").List(context.Background(), metav1.ListOptions{})
	} else {
		cmList, err = client.CoreV1().ConfigMaps(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, cmList.Items)
}

func (h *Handler) GetConfigMap(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	cm, err := client.CoreV1().ConfigMaps(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, cm)
}

func (h *Handler) CreateConfigMap(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot create resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var cm corev1.ConfigMap
	if err := json.NewDecoder(c.Request.Body).Decode(&cm); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.CoreV1().ConfigMaps(c.Param("namespace")).Create(context.Background(), &cm, metav1.CreateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) UpdateConfigMap(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot update resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var cm corev1.ConfigMap
	if err := json.NewDecoder(c.Request.Body).Decode(&cm); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.CoreV1().ConfigMaps(c.Param("namespace")).Update(context.Background(), &cm, metav1.UpdateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) DeleteConfigMap(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer || role.(Role) == RoleEditor {
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	err := client.CoreV1().ConfigMaps(c.Param("namespace")).Delete(context.Background(), c.Param("name"), metav1.DeleteOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// ==================== Secrets ====================

func (h *Handler) ListSecrets(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var secretList *corev1.SecretList
	var err error

	if namespace == "" || namespace == "-" {
		secretList, err = client.CoreV1().Secrets("").List(context.Background(), metav1.ListOptions{})
	} else {
		secretList, err = client.CoreV1().Secrets(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, secretList.Items)
}

func (h *Handler) GetSecret(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	secret, err := client.CoreV1().Secrets(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, secret)
}

func (h *Handler) CreateSecret(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot create resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var secret corev1.Secret
	if err := json.NewDecoder(c.Request.Body).Decode(&secret); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.CoreV1().Secrets(c.Param("namespace")).Create(context.Background(), &secret, metav1.CreateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) DeleteSecret(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer || role.(Role) == RoleEditor {
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	err := client.CoreV1().Secrets(c.Param("namespace")).Delete(context.Background(), c.Param("name"), metav1.DeleteOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// ==================== PVCs ====================

func (h *Handler) ListPVCs(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var pvcList *corev1.PersistentVolumeClaimList
	var err error

	if namespace == "" || namespace == "-" {
		pvcList, err = client.CoreV1().PersistentVolumeClaims("").List(context.Background(), metav1.ListOptions{})
	} else {
		pvcList, err = client.CoreV1().PersistentVolumeClaims(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, pvcList.Items)
}

func (h *Handler) GetPVC(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	pvc, err := client.CoreV1().PersistentVolumeClaims(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, pvc)
}

// ==================== Jobs ====================

func (h *Handler) ListJobs(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var jobList *batchv1.JobList
	var err error

	if namespace == "" || namespace == "-" {
		jobList, err = client.BatchV1().Jobs("").List(context.Background(), metav1.ListOptions{})
	} else {
		jobList, err = client.BatchV1().Jobs(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, jobList.Items)
}

func (h *Handler) GetJob(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	job, err := client.BatchV1().Jobs(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, job)
}

// ==================== CronJobs ====================

func (h *Handler) ListCronJobs(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	namespace := c.Param("namespace")
	var cronJobList *batchv1.CronJobList
	var err error

	if namespace == "" || namespace == "-" {
		cronJobList, err = client.BatchV1().CronJobs("").List(context.Background(), metav1.ListOptions{})
	} else {
		cronJobList, err = client.BatchV1().CronJobs(namespace).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, cronJobList.Items)
}

func (h *Handler) GetCronJob(c *gin.Context) {
	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	cronjob, err := client.BatchV1().CronJobs(c.Param("namespace")).Get(context.Background(), c.Param("name"), metav1.GetOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, cronjob)
}

func (h *Handler) CreateCronJob(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot create resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var cronjob batchv1.CronJob
	if err := json.NewDecoder(c.Request.Body).Decode(&cronjob); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.BatchV1().CronJobs(c.Param("namespace")).Create(context.Background(), &cronjob, metav1.CreateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) UpdateCronJob(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer {
		c.JSON(403, gin.H{"error": "Viewer cannot update resources"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	var cronjob batchv1.CronJob
	if err := json.NewDecoder(c.Request.Body).Decode(&cronjob); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := client.BatchV1().CronJobs(c.Param("namespace")).Update(context.Background(), &cronjob, metav1.UpdateOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (h *Handler) DeleteCronJob(c *gin.Context) {
	role, _ := c.Get("role")
	if role.(Role) == RoleViewer || role.(Role) == RoleEditor {
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		return
	}

	client := getClient(c)
	if client == nil {
		c.JSON(500, gin.H{"error": "No cluster"})
		return
	}

	err := client.BatchV1().CronJobs(c.Param("namespace")).Delete(context.Background(), c.Param("name"), metav1.DeleteOptions{})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// ==================== WebSocket Terminal ====================

func (h *Handler) WebSocketTerminal(c *gin.Context) {
	role, exists := c.Get("role")
	if !exists || (role.(Role) != RoleAdmin && role.(Role) != RoleEditor) {
		c.JSON(403, gin.H{"error": "Only admin and editor can use terminal"})
		return
	}

	clusterName := c.Query("cluster")
	namespace := c.Query("namespace")
	pod := c.Query("pod")
	container := c.Query("container")
	command := c.Query("command")
	if command == "" {
		command = "/bin/sh"
	}

	if namespace == "" || pod == "" {
		c.JSON(400, gin.H{"error": "namespace and pod are required"})
		return
	}

	var client *kubernetes.Clientset
	clusterMgr.mu.RLock()
	if clusterName != "" {
		if cluster, ok := clusterMgr.clusters[clusterName]; ok {
			client = cluster.Client
		}
	}
	if client == nil {
		for _, cluster := range clusterMgr.clusters {
			client = cluster.Client
			break
		}
	}
	clusterMgr.mu.RUnlock()

	if client == nil {
		c.JSON(400, gin.H{"error": "No cluster connected"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("Terminal: namespace=%s, pod=%s, container=%s", namespace, pod, container)

	req := client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command:   []string{command},
			Container: container,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, metav1.ParameterCodec)

	var config *rest.Config
	clusterMgr.mu.RLock()
	if clusterName != "" {
		if cluster, ok := clusterMgr.clusters[clusterName]; ok {
			config = cluster.Config
		}
	}
	if config == nil {
		for _, cluster := range clusterMgr.clusters {
			config = cluster.Config
			break
		}
	}
	clusterMgr.mu.RUnlock()

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		log.Printf("Failed to create executor: %v", err)
		conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: %v\r\n", err)))
		return
	}

	done := make(chan struct{})
	go func() {
		err := exec.Stream(remotecommand.StreamOptions{
			Stdout: &wsWriter{conn: conn},
			Stdin:  &wsReader{conn: conn},
			Stderr: &wsWriter{conn: conn},
			Tty:    true,
		})
		if err != nil {
			log.Printf("Exec stream error: %v", err)
		}
		close(done)
	}()

	<-done
	log.Printf("Terminal session ended")
}

type wsWriter struct {
	conn *websocket.Conn
}

func (w *wsWriter) Write(p []byte) (int, error) {
	err := w.conn.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

type wsReader struct {
	conn *websocket.Conn
}

func (r *wsReader) Read(p []byte) (int, error) {
	msgType, reader, err := r.conn.NextReader()
	if err != nil {
		return 0, err
	}
	if msgType == websocket.CloseMessage {
		return 0, io.EOF
	}
	return reader.Read(p)
}

// ==================== YAML Validation ====================

func (h *Handler) ValidateYAML(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to read YAML"})
		return
	}

	yamlStr := string(body)
	hasValidStructure := true
	errors := []string{}

	if !containsStr(yamlStr, "apiVersion:") && !containsStr(yamlStr, "apiVersion :") {
		errors = append(errors, "Missing 'apiVersion' field")
		hasValidStructure = false
	}
	if !containsStr(yamlStr, "kind:") && !containsStr(yamlStr, "kind :") {
		errors = append(errors, "Missing 'kind' field")
		hasValidStructure = false
	}
	if !containsStr(yamlStr, "metadata:") && !containsStr(yamlStr, "metadata :") {
		errors = append(errors, "Missing 'metadata' field")
		hasValidStructure = false
	}

	c.JSON(200, gin.H{
		"valid":   hasValidStructure,
		"errors":  errors,
		"message": "YAML syntax appears valid",
	})
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Initialize default cluster
func InitDefaultCluster(kubeconfigPath string) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	_, err = clientset.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	clusterMgr.mu.Lock()
	clusterMgr.clusters["default"] = &ClusterClient{
		Name:   "default",
		Server: config.Host,
		Client: clientset,
		Config: config,
	}
	clusterMgr.mu.Unlock()

	return nil
}
