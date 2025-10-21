package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func PrintBanner(conn net.Conn) {
	conn.Write([]byte("\033[8;24;80t"))
	conn.Write([]byte("\033[2J\033[1;1H"))
	conn.Write([]byte("\033[0m\r\n"))
	conn.Write([]byte("\033[0m\r\n"))
	conn.Write([]byte("   \033[38;5;15m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢤⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\r\n"))
	conn.Write([]byte("   \033[38;5;15m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠿⢿⡀⠀⠀⠀⠀\033[38;5;125m⣠⣶⣿⣷⠀⠀⠀⠀\r\n"))
	conn.Write([]byte("   \033[38;5;15m⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣦⣴⣿⡋⠀⠀⠈⢳⡄⠀\033[38;5;125m⢠⣾⣿⠁⠈⣿⡆⠀⠀⠀\r\n"))
	conn.Write([]byte(fmt.Sprintf("   \033[38;5;15m⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠿⠛⠉⠉⠁⠀⠀⠀⠹⡄\033[38;5;125m⣿⣿⣿⠀⠀⢹⡇     \033[38;5;15mMorte botnet v%s - \033[38;5;125mby .Abc_yxz.\r\n", config.Version)))
	conn.Write([]byte("   \033[38;5;15m⠀⠀⠀⠀⠀⣠⣾⡿⠋⠁\033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⠀⣰⣏⢻⣿⣿⡆⠀⠸⣿⠀⠀⠀\r\n"))
	conn.Write([]byte("   \033[38;5;15m⠀⠀⠀⢀⣴⠟⠁  \033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣆⠹⣿⣷⠀⢘⣿⠀⠀⠀\r\n"))
	conn.Write([]byte("   \033[38;5;15m⠀⠀⢀⡾⠁\033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠋⠉⠛⠂⠹⠿⣲⣿⣿⣧⠀⠀\r\n"))
	conn.Write([]byte("   \033[38;5;15m⠀⢠⠏\033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⣿⣷⣾⣿⡇⢀⠀⣼⣿⣿⣿⣧⠀\r\n"))
	conn.Write([]byte("   \033[38;5;15m⠰⠃\033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡘⢿⣿⣿⣿⠀\r\n"))
	conn.Write([]byte("   \033[38;5;15m⠁\033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣷⡈⠿⢿⣿⡆\r\n"))
	conn.Write([]byte("   \033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⢙⠛⣿⣿⣿⣿⡟⠀⡿⠀⠀⢀⣿⡇\r\n"))
	conn.Write([]byte("   \033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣶⣤⣉⣛⠻⠇⢠⣿⣾⣿⡄⢻⡇\r\n"))
	conn.Write([]byte("   \033[38;5;125m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣦⣤⣾⣿⣿⣿⣿⣆⠁\r\n"))
	conn.Write([]byte("\033[0m\r\n"))
	conn.Write([]byte("\033[0m\r\n"))
}

func PrintMethods(conn net.Conn) {
	conn.Write([]byte("\033[8;24;80t"))
	conn.Write([]byte("\033[2J\033[1;1H\r\n"))
	conn.Write([]byte("\033[0m\r\n"))
	conn.Write([]byte("   \033[38;5;125mMethods\x1b[38;5;231m:\033[0m\r\n"))
	conn.Write([]byte("     \033[38;5;15m.tcpflood   \033[38;5;125m| \033[38;5;15mSimple syn+ack flood to exhaust server resources\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.tcpboom    \033[38;5;125m| \033[38;5;15mEnhanced TCP flood with crafted TCP options for bypass\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.tcpkiller  \033[38;5;125m| \033[38;5;15mSyn+ack+rst packets to disrupt active TCP connections\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.tcpbypass  \033[38;5;125m| \033[38;5;15mRandomized tcp flag flood to bypass firewall\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.frag       \033[38;5;125m| \033[38;5;15mTCP fragmentation flood bypass packet inspection and WAF\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.tcpxmas    \033[38;5;125m| \033[38;5;15mXmas packet flood using urg+psh+fin to crash target\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.udpplain   \033[38;5;125m| \033[38;5;15mPlain udp flood with random or static payload\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.std        \033[38;5;125m| \033[38;5;15mUdp flood with hex payload to overload bandwidth\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.udpbypass  \033[38;5;125m| \033[38;5;15mRandom length udp flood to bypass basic filtering\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.vse        \033[38;5;125m| \033[38;5;15mValve Source Engine query flood to disrupt game servers\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.mixamp     \033[38;5;125m| \033[38;5;15mHigh-volume amplification attack (DNS/NTP/STUN)\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.discord    \033[38;5;125m| \033[38;5;15mUdp flood using Discord payload to mimic voice traffic\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15m.http       \033[38;5;125m| \033[38;5;15mSimple http flood optimized for higher requests\033[38;5;125m.\r\n"))
	conn.Write([]byte("\033[0m\r\n"))
}

func PrintHelp(conn net.Conn) {
	conn.Write([]byte("\033[8;24;80t"))
	conn.Write([]byte("\033[2J\033[1;1H\r\n"))
	conn.Write([]byte("   \033[38;5;125mCommands\x1b[38;5;231m:\033[0m\r\n"))
	conn.Write([]byte("     \033[38;5;15mHelp        \033[38;5;125m| \033[38;5;15mList of available commands\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mMethods     \033[38;5;125m| \033[38;5;15mList of available methods\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mOngoing     \033[38;5;125m| \033[38;5;15mShowing attacks currently in running\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mPlan        \033[38;5;125m| \033[38;5;15mFor showing your plan\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mStop        \033[38;5;125m| \033[38;5;15mFor stoping all attacks\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mAttacks     \033[38;5;125m| \033[38;5;15mFor enable/disable attacks\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mAdduser     \033[38;5;125m| \033[38;5;15mFor adding user\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mRemoveuser  \033[38;5;125m| \033[38;5;15mFor removing user\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mUserlist    \033[38;5;125m| \033[38;5;15mShowing all users\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mLogs        \033[38;5;125m| \033[38;5;15mFor clearing logs\033[38;5;125m.\r\n"))
	conn.Write([]byte("     \033[38;5;15mLogout      \033[38;5;125m| \033[38;5;15mFor logging out\033[38;5;125m.\r\n"))
}

func PrintPlan(conn net.Conn, u *UserInfo) {
	if u == nil {
		conn.Write([]byte("\x1b[1;31mError fetching plan information.\033[0m\r\n"))
		return
	}

	expiryStr := calculateExpiry(u.last_paid, u.intvl)
	adminStr := "No"
	if u.admin == 1 {
		adminStr = "Yes"
	}
	apiStr := "No"
	if u.api_access == 1 {
		apiStr = "Yes"
	}

	apiKey, err := database.GetUserAPIKey(u.username)
	if err != nil {
		apiKey = "N/A"
	}

	lines := []string{
		"\r\n",
		fmt.Sprintf(" \x1b[38;5;231m[ \033[38;5;125mAccount Info \x1b[38;5;231m]\r\n"),
		fmt.Sprintf("  \033[38;5;125m║\x1b[39m  \x1b[38;5;231mUsername \x1b[39m\033[38;5;125m··········· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", u.username),
		fmt.Sprintf("  \033[38;5;125m║\x1b[39m  \x1b[38;5;231mMax Bots \x1b[39m\033[38;5;125m··········· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%d \x1b[38;5;231m]\r\n", u.maxBots),
		fmt.Sprintf("  \033[38;5;125m║\x1b[39m  \x1b[38;5;231mDuration \x1b[39m\033[38;5;125m··········· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%d \x1b[38;5;231m]\r\n", u.duration_limit),
		fmt.Sprintf("  \033[38;5;125m║\x1b[39m  \x1b[38;5;231mCooldown \x1b[39m\033[38;5;125m··········· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%d \x1b[38;5;231m]\r\n", u.cooldown),
		fmt.Sprintf("  \033[38;5;125m║\x1b[39m  \x1b[38;5;231mExpired \x1b[39m\033[38;5;125m············ \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", expiryStr),
		fmt.Sprintf("  \033[38;5;125m║\x1b[39m  \x1b[38;5;231mAdmin \x1b[39m\033[38;5;125m·············· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", adminStr),
		fmt.Sprintf("  \033[38;5;125m║\x1b[39m  \x1b[38;5;231mApi Access \x1b[39m\033[38;5;125m········· \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", apiStr),
		fmt.Sprintf("  \033[38;5;125m║\x1b[39m  \x1b[38;5;231mApi Key \x1b[39m\033[38;5;125m············ \x1b[38;5;231m[ \x1b[39m\033[38;5;125m%s \x1b[38;5;231m]\r\n", apiKey),
		"\r\n",
	}

	for _, line := range lines {
		conn.Write([]byte(line))
		time.Sleep(30 * time.Millisecond)
	}
}

func printTable(conn net.Conn, columns []string, dataRows [][]string) {
	maxVisibleLengths := make([]int, len(columns))
	for i, header := range columns {
		maxVisibleLengths[i] = visibleLength(header)
	}
	for _, row := range dataRows {
		for i, cell := range row {
			cellLen := visibleLength(cell)
			if cellLen > maxVisibleLengths[i] {
				maxVisibleLengths[i] = cellLen
			}
		}
	}

	currentSessionWidth := 80
	totalTableWidth := getTotalTableWidth(maxVisibleLengths)
	if totalTableWidth > currentSessionWidth {
		conn.Write([]byte(fmt.Sprintf("\x1b[8;24;%dt", totalTableWidth)))
		time.Sleep(100 * time.Millisecond)
	}

	printHLine := func(left, middle, right string) {
		conn.Write([]byte("\x1b[38;5;231m" + left))
		for i, maxLen := range maxVisibleLengths {
			if i > 0 {
				conn.Write([]byte(middle))
			}
			conn.Write([]byte(strings.Repeat("═", maxLen+2)))
		}
		conn.Write([]byte("\x1b[38;5;231m" + right + "\r\n"))
	}

	printHLine("╔", "╦", "╗")

	conn.Write([]byte("\x1b[38;5;231m║"))
	for i, header := range columns {
		visibleLen := visibleLength(header)
		padding := maxVisibleLengths[i] - visibleLen
		conn.Write([]byte(" " + header + strings.Repeat(" ", padding) + " \x1b[38;5;231m║"))
	}
	conn.Write([]byte("\r\n"))

	printHLine("╠", "╬", "╣")

	for _, row := range dataRows {
		conn.Write([]byte("\x1b[38;5;231m║"))
		for i, cell := range row {
			visibleLen := visibleLength(cell)
			padding := maxVisibleLengths[i] - visibleLen
			conn.Write([]byte(" " + cell + strings.Repeat(" ", padding) + " \x1b[38;5;231m║"))
		}
		conn.Write([]byte("\r\n"))
	}

	printHLine("╚", "╩", "╝")
}

func visibleLength(s string) int {
	return len(ansiRegexp.ReplaceAllString(s, ""))
}

func getTotalTableWidth(columnWidths []int) int {
	totalWidth := 1
	for _, w := range columnWidths {
		totalWidth += 2 + w + 1
	}
	return totalWidth
}
