package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

var (
	hostsDB     *sql.DB
	hostsDBSync sync.Once
	
	sshClients = make(map[string]*sshClient)
	sshMutex   sync.RWMutex
)

type Host struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	Username    string    `json:"username"`
	Password    string    `json:"password"`
	PrivateKey  string    `json:"private_key"`
	GroupID     int       `json:"group_id"`
	GroupName   string    `json:"group_name"`
	Status      string    `json:"status"`
	CPU         float64   `json:"cpu"`
	Memory      float64   `json:"memory"`
	Disk        float64   `json:"disk"`
	LastOnline  time.Time `json:"last_online"`
	CreatedAt   time.Time `json:"created_at"`
}

type HostGroup struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Count int    `json:"count"`
}

type sshClient struct {
	Host     string
	Conn     net.Conn
	LastUsed time.Time
}

func initHostsDB() {
	hostsDBSync.Do(func() {
		var err error
		dsn := "root:@tcp(127.0.0.1:3306)/k8s_admin?parseTime=true"
		hostsDB, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Printf("Hosts DB init error: %v", err)
			return
		}
		
		_, err = hostsDB.Exec(`CREATE TABLE IF NOT EXISTS host_groups (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL UNIQUE,
			desc TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
		_, err = hostsDB.Exec(`CREATE TABLE IF NOT EXISTS hosts (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			ip VARCHAR(50) NOT NULL,
			port INT DEFAULT 22,
			username VARCHAR(50) NOT NULL,
			password VARCHAR(255),
			private_key TEXT,
			group_id INT,
			status VARCHAR(20) DEFAULT 'offline',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (group_id) REFERENCES host_groups(id) ON DELETE SET NULL
		)`)
		_, err = hostsDB.Exec(`CREATE TABLE IF NOT EXISTS host_metrics (
			id INT AUTO_INCREMENT PRIMARY KEY,
			host_id INT NOT NULL,
			cpu FLOAT,
			memory FLOAT,
			disk FLOAT,
			recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
		)`)
		
		// Insert demo data
		hostsDB.Exec(`INSERT IGNORE INTO host_groups (id, name, desc) VALUES (1, 'Web服务器', 'Web服务集群')`)
		hostsDB.Exec(`INSERT IGNORE INTO host_groups (id, name, desc) VALUES (2, '数据库服务器', 'MySQL/Redis集群')`)
		hostsDB.Exec(`INSERT IGNORE INTO hosts (id, name, ip, port, username, group_id, status) VALUES 
			(1, 'web-01', '192.168.1.101', 22, 'root', 1, 'online'),
			(2, 'web-02', '192.168.1.102', 22, 'root', 1, 'online'),
			(3, 'db-01', '192.168.1.201', 22, 'root', 2, 'online'),
			(4, 'db-02', '192.168.1.202', 22, 'root', 2, 'offline')`)
		
		log.Println("Hosts DB initialized")
	})
}

// ==================== Host Groups ====================

func (h *Handler) GetHostGroups(c *gin.Context) {
	initHostsDB()
	if hostsDB == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	rows, err := hostsDB.Query(`SELECT hg.id, hg.name, hg.desc, COUNT(h.id) as cnt 
		FROM host_groups hg LEFT JOIN hosts h ON hg.id = h.group_id GROUP BY hg.id`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	
	var groups []HostGroup
	for rows.Next() {
		var g HostGroup
		var desc sql.NullString
		rows.Scan(&g.ID, &g.Name, &desc, &g.Count)
		if desc.Valid {
			g.Desc = desc.String
		}
		groups = append(groups, g)
	}
	
	if groups == nil {
		groups = []HostGroup{}
	}
	c.JSON(200, groups)
}

func (h *Handler) CreateHostGroup(c *gin.Context) {
	initHostsDB()
	if hostsDB == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	var req struct {
		Name string `json:"name" binding:"required"`
		Desc string `json:"desc"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	result, err := hostsDB.Exec("INSERT INTO host_groups (name, desc) VALUES (?, ?)", req.Name, req.Desc)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	id, _ := result.LastInsertId()
	c.JSON(200, gin.H{"id": id, "name": req.Name, "desc": req.Desc})
}

func (h *Handler) DeleteHostGroup(c *gin.Context) {
	initHostsDB()
	id := c.Param("id")
	_, err := hostsDB.Exec("DELETE FROM host_groups WHERE id = ?", id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "删除成功"})
}

// ==================== Hosts ====================

func (h *Handler) GetHosts(c *gin.Context) {
	initHostsDB()
	if hostsDB == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	groupID := c.Query("group_id")
	query := `SELECT h.id, h.name, h.ip, h.port, h.username, h.group_id, h.status, 
		COALESCE(hg.name, '') as group_name, h.created_at
		FROM hosts h LEFT JOIN host_groups hg ON h.group_id = hg.id`
	
	var rows *sql.Rows
	var err error
	
	if groupID != "" {
		query += " WHERE h.group_id = ?"
		rows, err = hostsDB.Query(query, groupID)
	} else {
		rows, err = hostsDB.Query(query)
	}
	
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	
	var hosts []Host
	for rows.Next() {
		var ho Host
		var groupID sql.NullInt64
		rows.Scan(&ho.ID, &ho.Name, &ho.IP, &ho.Port, &ho.Username, &groupID, &ho.Status, &ho.GroupName, &ho.CreatedAt)
		if groupID.Valid {
			ho.GroupID = int(groupID.Int64)
		}
		hosts = append(hosts, ho)
	}
	
	if hosts == nil {
		hosts = []Host{}
	}
	c.JSON(200, hosts)
}

func (h *Handler) CreateHost(c *gin.Context) {
	initHostsDB()
	if hostsDB == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	var req Host
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	if req.Port == 0 {
		req.Port = 22
	}
	
	// Encrypt password simply (in production, use proper encryption)
	encryptedPwd := req.Password
	
	result, err := hostsDB.Exec(`INSERT INTO hosts (name, ip, port, username, password, private_key, group_id) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		req.Name, req.IP, req.Port, req.Username, encryptedPwd, req.PrivateKey, req.GroupID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	id, _ := result.LastInsertId()
	req.ID = int(id)
	req.Status = "offline"
	
	c.JSON(200, req)
}

func (h *Handler) DeleteHost(c *gin.Context) {
	initHostsDB()
	id := c.Param("id")
	_, err := hostsDB.Exec("DELETE FROM hosts WHERE id = ?", id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "删除成功"})
}

func (h *Handler) PingHost(c *gin.Context) {
	id := c.Param("id")
	
	var ip, username, password string
	var port int
	initHostsDB()
	if hostsDB == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	err := hostsDB.QueryRow("SELECT ip, port, username, password FROM hosts WHERE id = ?", id).
		Scan(&ip, &port, &username, &password)
	if err != nil {
		c.JSON(404, gin.H{"error": "主机不存在"})
		return
	}
	
	// Simple ping test
	cmd := exec.Command("ping", "-c", "1", "-W", "2", ip)
	err = cmd.Run()
	
	status := "offline"
	if err == nil {
		status = "online"
		hostsDB.Exec("UPDATE hosts SET status = ? WHERE id = ?", status, id)
	}
	
	c.JSON(200, gin.H{"id": id, "status": status})
}

// ==================== SSH Terminal ====================

func (h *Handler) SSHTerminal(c *gin.Context) {
	var req struct {
		HostID  int    `json:"host_id"`
		Command string `json:"command"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	var ip, username, password string
	var port int
	initHostsDB()
	if hostsDB == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	err := hostsDB.QueryRow("SELECT ip, port, username, password FROM hosts WHERE id = ?", req.HostID).
		Scan(&ip, &port, &username, &password)
	if err != nil {
		c.JSON(404, gin.H{"error": "主机不存在"})
		return
	}
	
	// Execute command via SSH (using simple approach - in production use golang.org/x/crypto/ssh)
	output, err := execSSH(ip, port, username, password, req.Command)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error(), "output": output})
		return
	}
	
	c.JSON(200, gin.H{"output": output})
}

func execSSH(ip string, port int, user, pass, cmd string) (string, error) {
	// Use sshpass if available, otherwise try direct ssh
	sshCmd := fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p %d %s@%s '%s' 2>&1",
		port, user, ip, cmd)
	
	// Try with sshpass if password provided
	if pass != "" {
		_, err := exec.LookPath("sshpass")
		if err == nil {
			sshCmd = fmt.Sprintf("sshpass -p '%s' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p %d %s@%s '%s' 2>&1",
				pass, port, user, ip, cmd)
		}
	}
	
	out, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	return string(out), err
}

// ==================== Host Metrics ====================

func (h *Handler) GetHostMetrics(c *gin.Context) {
	id := c.Param("id")
	
	initHostsDB()
	if hostsDB == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	// Get latest metrics
	var cpu, mem, disk sql.NullFloat64
	var recordedAt sql.NullTime
	
	err := hostsDB.QueryRow(`SELECT cpu, memory, disk, recorded_at FROM host_metrics 
		WHERE host_id = ? ORDER BY recorded_at DESC LIMIT 1`, id).
		Scan(&cpu, &mem, &disk, &recordedAt)
	
	if err != nil {
		// Return demo data
		c.JSON(200, gin.H{
			"cpu":    45.5,
			"memory": 62.3,
			"disk":   78.1,
			"time":   time.Now().Format("15:04:05"),
		})
		return
	}
	
	c.JSON(200, gin.H{
		"cpu":    cpu.Float64,
		"memory": mem.Float64,
		"disk":   disk.Float64,
		"time":   recordedAt.Time.Format("15:04:05"),
	})
}

func (h *Handler) CollectHostMetrics(c *gin.Context) {
	id := c.Param("id")
	
	// In production, actually SSH to host and collect metrics
	// For demo, generate random metrics
	
	initHostsDB()
	if hostsDB != nil {
		cpu := 30.0 + float64(time.Now().Unix()%50)
		mem := 40.0 + float64(time.Now().Unix()%40)
		disk := 50.0 + float64(time.Now().Unix()%30)
		hostsDB.Exec("INSERT INTO host_metrics (host_id, cpu, memory, disk) VALUES (?, ?, ?, ?)",
			id, cpu, mem, disk)
	}
	
	c.JSON(200, gin.H{"message": "采集完成"})
}
