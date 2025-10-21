package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var ipInfoCache = make(map[string]*IPInfo)

type IPInfo struct {
	Country string `json:"country"`
	Org     string `json:"org"`
	Region  string `json:"region"`
}

func getIPInfo(ip string, token string) (*IPInfo, error) {
	if info, ok := ipInfoCache[ip]; ok {
		return info, nil
	}
	url := fmt.Sprintf("https://ipinfo.io/%s?token=%s", ip, token)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var info IPInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, err
	}
	ipInfoCache[ip] = &info
	return &info, nil
}

func calculateExpiry(lastPaid int, intvl int) string {
	if intvl == 0 {
		return "Unlimited"
	}
	currentTime := time.Now().Unix()
	expiryTime := int64(lastPaid) + int64(intvl)*24*60*60
	if currentTime >= expiryTime {
		return "Expired"
	}
	timeLeft := expiryTime - currentTime
	days := timeLeft / (24 * 60 * 60)
	if days > 0 {
		return fmt.Sprintf("%d days", days)
	}
	hours := (timeLeft % (24 * 60 * 60)) / (60 * 60)
	if hours > 0 {
		return fmt.Sprintf("%d hours", hours)
	}
	minutes := (timeLeft % (60 * 60)) / 60
	return fmt.Sprintf("%d minutes", minutes)
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}
