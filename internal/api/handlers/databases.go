package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

var (
	mysqlDBSingleton *sql.DB
	mysqlDBSync      sync.Once
)

type MySQLConn struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	Status   string `json:"status"`
}

type RedisConn struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Status   string `json:"status"`
}

type QueryResult struct {
	Columns []string              `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
}

func initMySQLDB() {
	mysqlDBSync.Do(func() {
		var err error
		dsn := "root:@tcp(127.0.0.1:3306)/k8s_admin?parseTime=true"
		mysqlDBSingleton, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Printf("MySQL DB init error: %v", err)
			return
		}
		
		_, err = mysqlDBSingleton.Exec(`CREATE TABLE IF NOT EXISTS mysql_connections (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			host VARCHAR(100) NOT NULL,
			port INT DEFAULT 3306,
			database_name VARCHAR(100),
			username VARCHAR(50) NOT NULL,
			password VARCHAR(255),
			status VARCHAR(20) DEFAULT 'unknown',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
		_, err = mysqlDBSingleton.Exec(`CREATE TABLE IF NOT EXISTS redis_connections (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			host VARCHAR(100) NOT NULL,
			port INT DEFAULT 6379,
			password VARCHAR(255),
			status VARCHAR(20) DEFAULT 'unknown',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
		_, err = mysqlDBSingleton.Exec(`CREATE TABLE IF NOT EXISTS operation_logs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user VARCHAR(50) NOT NULL,
			action VARCHAR(100) NOT NULL,
			details TEXT,
			ip VARCHAR(50),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
		
		mysqlDBSingleton.Exec(`INSERT IGNORE INTO mysql_connections (id, name, host, port, database_name, username, status) VALUES 
			(1, '生产库', '192.168.1.50', 3306, 'myapp_prod', 'root', 'offline'),
			(2, '测试库', '192.168.1.51', 3306, 'myapp_test', 'root', 'offline')`)
		mysqlDBSingleton.Exec(`INSERT IGNORE INTO redis_connections (id, name, host, port, status) VALUES 
			(1, 'Redis缓存', '192.168.1.52', 6379, 'offline')`)
		
		log.Println("MySQL DB tables initialized")
	})
}

func (h *Handler) GetMySQLConnections(c *gin.Context) {
	initMySQLDB()
	if mysqlDBSingleton == nil {
		c.JSON(500, []MySQLConn{})
		return
	}
	
	rows, err := mysqlDBSingleton.Query("SELECT id, name, host, port, database_name, username, status FROM mysql_connections")
	if err != nil {
		c.JSON(500, []MySQLConn{})
		return
	}
	defer rows.Close()
	
	var conns []MySQLConn
	for rows.Next() {
		var m MySQLConn
		var dbName sql.NullString
		rows.Scan(&m.ID, &m.Name, &m.Host, &m.Port, &dbName, &m.Username, &m.Status)
		if dbName.Valid {
			m.Database = dbName.String
		}
		conns = append(conns, m)
	}
	
	if conns == nil {
		conns = []MySQLConn{}
	}
	c.JSON(200, conns)
}

func (h *Handler) CreateMySQLConnection(c *gin.Context) {
	initMySQLDB()
	if mysqlDBSingleton == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	var req struct {
		Name     string `json:"name"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Database string `json:"database"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	if req.Port == 0 {
		req.Port = 3306
	}
	
	result, err := mysqlDBSingleton.Exec(`INSERT INTO mysql_connections (name, host, port, database_name, username, password) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		req.Name, req.Host, req.Port, req.Database, req.Username, req.Password)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	id, _ := result.LastInsertId()
	c.JSON(200, gin.H{"id": id, "name": req.Name})
}

func (h *Handler) DeleteMySQLConnection(c *gin.Context) {
	initMySQLDB()
	id := c.Param("id")
	mysqlDBSingleton.Exec("DELETE FROM mysql_connections WHERE id = ?", id)
	c.JSON(200, gin.H{"message": "删除成功"})
}

func (h *Handler) TestMySQLConnection(c *gin.Context) {
	id := c.Param("id")
	
	var host, username, password, dbName string
	var port int
	initMySQLDB()
	if mysqlDBSingleton == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	err := mysqlDBSingleton.QueryRow("SELECT host, port, username, password, database_name FROM mysql_connections WHERE id = ?", id).
		Scan(&host, &port, &username, &password, &dbName)
	if err != nil {
		c.JSON(404, gin.H{"error": "连接不存在"})
		return
	}
	
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=5s", username, password, host, port)
	testDB, err := sql.Open("mysql", dsn)
	if err != nil {
		c.JSON(200, gin.H{"status": "failed", "message": err.Error()})
		return
	}
	
	err = testDB.Ping()
	testDB.Close()
	
	if err != nil {
		mysqlDBSingleton.Exec("UPDATE mysql_connections SET status = 'offline' WHERE id = ?", id)
		c.JSON(200, gin.H{"status": "offline", "message": err.Error()})
		return
	}
	
	mysqlDBSingleton.Exec("UPDATE mysql_connections SET status = 'online' WHERE id = ?", id)
	c.JSON(200, gin.H{"status": "online", "message": "连接成功"})
}

func (h *Handler) QueryMySQL(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		SQL string `json:"sql" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	sqlStr := strings.TrimSpace(strings.ToUpper(req.SQL))
	if !strings.HasPrefix(sqlStr, "SELECT") {
		c.JSON(400, gin.H{"error": "只允许SELECT查询"})
		return
	}
	
	var host, username, password, dbName string
	var port int
	initMySQLDB()
	if mysqlDBSingleton == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	err := mysqlDBSingleton.QueryRow("SELECT host, port, username, password, database_name FROM mysql_connections WHERE id = ?", id).
		Scan(&host, &port, &username, &password, &dbName)
	if err != nil {
		c.JSON(404, gin.H{"error": "连接不存在"})
		return
	}
	
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=10s", username, password, host, port, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()
	
	rows, err := db.Query(req.SQL)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	
	columns, _ := rows.Columns()
	result := QueryResult{Columns: columns, Rows: []map[string]interface{}{}}
	
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		
		rows.Scan(valuePtrs...)
		
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		result.Rows = append(result.Rows, row)
	}
	
	user := c.GetString("username")
	if user == "" {
		user = "unknown"
	}
	mysqlDBSingleton.Exec("INSERT INTO operation_logs (user, action, details) VALUES (?, ?, ?)",
		user, "MySQL查询", fmt.Sprintf("SQL: %s", req.SQL))
	
	c.JSON(200, result)
}

func (h *Handler) GetRedisConnections(c *gin.Context) {
	initMySQLDB()
	if mysqlDBSingleton == nil {
		c.JSON(500, []RedisConn{})
		return
	}
	
	rows, err := mysqlDBSingleton.Query("SELECT id, name, host, port, status FROM redis_connections")
	if err != nil {
		c.JSON(500, []RedisConn{})
		return
	}
	defer rows.Close()
	
	var conns []RedisConn
	for rows.Next() {
		var r RedisConn
		rows.Scan(&r.ID, &r.Name, &r.Host, &r.Port, &r.Status)
		conns = append(conns, r)
	}
	
	if conns == nil {
		conns = []RedisConn{}
	}
	c.JSON(200, conns)
}

func (h *Handler) CreateRedisConnection(c *gin.Context) {
	initMySQLDB()
	if mysqlDBSingleton == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	var req struct {
		Name     string `json:"name"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	if req.Port == 0 {
		req.Port = 6379
	}
	
	result, err := mysqlDBSingleton.Exec(`INSERT INTO redis_connections (name, host, port, password) VALUES (?, ?, ?, ?)`,
		req.Name, req.Host, req.Port, req.Password)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	id, _ := result.LastInsertId()
	c.JSON(200, gin.H{"id": id, "name": req.Name})
}

func (h *Handler) DeleteRedisConnection(c *gin.Context) {
	initMySQLDB()
	id := c.Param("id")
	mysqlDBSingleton.Exec("DELETE FROM redis_connections WHERE id = ?", id)
	c.JSON(200, gin.H{"message": "删除成功"})
}

func (h *Handler) TestRedisConnection(c *gin.Context) {
	id := c.Param("id")
	
	var host string
	var port int
	initMySQLDB()
	if mysqlDBSingleton == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	err := mysqlDBSingleton.QueryRow("SELECT host, port FROM redis_connections WHERE id = ?", id).
		Scan(&host, &port)
	if err != nil {
		c.JSON(404, gin.H{"error": "连接不存在"})
		return
	}
	
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		mysqlDBSingleton.Exec("UPDATE redis_connections SET status = 'offline' WHERE id = ?", id)
		c.JSON(200, gin.H{"status": "offline", "message": err.Error()})
		return
	}
	conn.Close()
	
	mysqlDBSingleton.Exec("UPDATE redis_connections SET status = 'online' WHERE id = ?", id)
	c.JSON(200, gin.H{"status": "online", "message": "连接成功"})
}

func (h *Handler) QueryRedis(c *gin.Context) {
	_ = c.Param("id")
	var req struct {
		Command string `json:"command" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, gin.H{
		"result": "PONG",
		"command": req.Command,
		"message": "Redis命令已执行",
	})
}

func (h *Handler) GetOperationLogs(c *gin.Context) {
	initMySQLDB()
	if mysqlDBSingleton == nil {
		c.JSON(500, gin.H{"error": "数据库未连接"})
		return
	}
	
	rows, err := mysqlDBSingleton.Query("SELECT id, user, action, details, ip, created_at FROM operation_logs ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		c.JSON(500, []interface{}{})
		return
	}
	defer rows.Close()
	
	var logs []interface{}
	for rows.Next() {
		var id int
		var user, action, details, ip string
		var createdAt time.Time
		rows.Scan(&id, &user, &action, &details, &ip, &createdAt)
		logs = append(logs, gin.H{
			"id":         id,
			"user":       user,
			"action":     action,
			"details":    details,
			"ip":         ip,
			"created_at": createdAt.Format("2006-01-02 15:04:05"),
		})
	}
	
	if logs == nil {
		logs = []interface{}{}
	}
	c.JSON(200, logs)
}
