package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var (
	db     *sql.DB
	dbOnce sync.Once
)

func initDB() {
	dbOnce.Do(func() {
		var err error
		dsn := "root:@tcp(127.0.0.1:3306)/k8s_admin?parseTime=true"
		db, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Printf("Failed to connect to MySQL: %v", err)
			return
		}
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)
		
		// Create tables
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			role VARCHAR(20) NOT NULL DEFAULT 'viewer',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
		if err != nil {
			log.Printf("Failed to create users table: %v", err)
		}
		
		// Insert default admin if not exists
		_, err = db.Exec(`INSERT IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`,
			"admin", "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", "admin")
		if err != nil {
			log.Printf("Failed to insert default admin: %v", err)
		}
		
		log.Println("MySQL connected successfully")
	})
}

// ==================== MySQL User Operations ====================

func (h *Handler) getUserFromDB(username string) (*User, error) {
	initDB()
	if db == nil {
		return nil, fmt.Errorf("database not connected")
	}
	
	var user User
	err := db.QueryRow("SELECT username, password, role FROM users WHERE username = ?", username).
		Scan(&user.Username, &user.Password, &user.Role)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (h *Handler) getAllUsersFromDB() ([]User, error) {
	initDB()
	if db == nil {
		return nil, fmt.Errorf("database not connected")
	}
	
	rows, err := db.Query("SELECT username, password, role FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.Password, &u.Role); err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

func (h *Handler) createUserInDB(username, password, role string) error {
	initDB()
	if db == nil {
		return fmt.Errorf("database not connected")
	}
	
	hashed := hashPassword(password)
	_, err := db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
		username, hashed, role)
	return err
}

func (h *Handler) updateUserInDB(username, password, role string) error {
	initDB()
	if db == nil {
		return fmt.Errorf("database not connected")
	}
	
	if password != "" {
		hashed := hashPassword(password)
		_, err := db.Exec("UPDATE users SET password = ?, role = ? WHERE username = ?",
			hashed, role, username)
		return err
	}
	_, err := db.Exec("UPDATE users SET role = ? WHERE username = ?", role, username)
	return err
}

func (h *Handler) deleteUserFromDB(username string) error {
	initDB()
	if db == nil {
		return fmt.Errorf("database not connected")
	}
	
	_, err := db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}
