package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/getlantern/systray"
)

func main() {
	
	// Khởi động systray
    systray.Run(onReady, nil)
}

func sendRequest() error {
	// Xây dựng body của request
	formData := url.Values{}
	formData.Set("dst", "http://v1.awingconnect.vn/Success")
	formData.Set("password", "Awing15-15@2023")
	formData.Set("popup", "false")
	formData.Set("username", "awing15-15")

	// Xây dựng request
	req, err := http.NewRequest("POST", "http://rescue.wi-mesh.vn/login", bytes.NewBufferString(formData.Encode()))
	if err != nil {
		LogError("Error creating request")
	}

	// Thiết lập các headers
	req.Header.Set("documentLifecycle", "active")
	req.Header.Set("frameType", "outermost_frame")
	req.Header.Set("initiator", "http://v1.awingconnect.vn")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", "http://v1.awingconnect.vn")
	req.Header.Set("Referer", "http://v1.awingconnect.vn/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

	// Gửi request và xử lý response
	client := &http.Client{}
	_ , err = client.Do(req)
	if err != nil {
		// LogError("request host error")
	}

	return err
}

// Hàm kiểm tra xem ngày đã hết hạn chưa
func isExpired(dateStr string) bool {
	// Định dạng datetime trong chuỗi đầu vào
	const layout = "2006-01-02 15:04:05"

	// Parse chuỗi datetime thành time.Time
	loc, _ := time.LoadLocation("Local")

	parsedTime, err := time.ParseInLocation(layout, dateStr, loc)
	if err != nil {
		LogError("Error parsing date: " + err.Error())
		return true
	}

	//fmt.Println("Thời gian hết hạn: ", parsedTime)
	currentTime := time.Now()
	//fmt.Println("Thời gian hiện tại: ", currentTime)

	// Kiểm tra xem thời gian đã qua hay chưa
	expired := parsedTime.Before(currentTime)
	if(expired) {
		LogError("Key is expried")
	}

	return expired
}

func getMacAddress() string {
	// Lấy tất cả các giao diện mạng trên hệ thống
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	// Lặp qua từng giao diện mạng và in ra MAC address
	for _, iface := range interfaces {

		if iface.HardwareAddr.String() != "" {
			if(iface.Name == "Ethernet") {
				
				address := iface.HardwareAddr.String()
				return strings.ToUpper(strings.ReplaceAll(address, ":", "-"))
			}
		}
	}
	return ""
}
// Hàm để đọc 2 dòng đầu tiên của file
func readFirstTwoLines(filePath string) (string, string, error) {
	// Mở file
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	// Sử dụng bufio.Scanner để đọc các dòng
	scanner := bufio.NewScanner(file)
	var firstLine, secondLine string

	// Đọc dòng đầu tiên
	if scanner.Scan() {
		firstLine = scanner.Text()
	} else if err := scanner.Err(); err != nil {
		return "", "", err
	}

	// Đọc dòng thứ hai
	if scanner.Scan() {
		secondLine = scanner.Text()
	} else if err := scanner.Err(); err != nil {
		return "", "", err
	}

	return firstLine, secondLine, nil
}


func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}


func AES_ECB_Decrypt(ciphertext, key []byte) ([]byte, error) {

	defer func() {
		if r := recover(); r != nil {
		  LogError("Decryption error: in")
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	// Decrypt each block
	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertext[i:i+block.BlockSize()])
	}

	// Remove padding
	padding := int(plaintext[len(plaintext)-1])
	return plaintext[:len(plaintext)-padding], nil
}

func isNetworkAvailable() bool {
	// Try to reach a reliable URL (e.g., Google DNS or Google website)
	url := "http://google.com"
	client := http.Client{
		Timeout: 5 * time.Second, // Set a timeout to avoid hanging indefinitely
	}

	// Send a GET request
	resp, err := client.Head(url)
	if err != nil {
		return false // If there's an error, no internet connection
	}
	defer resp.Body.Close()

	// Check if the status code indicates success
	return resp.StatusCode == http.StatusOK
}

//go:embed icon.ico
var iconData []byte

func getIcon() []byte {
    if iconData == nil {
        log.Fatal("Icon data is empty")
    }
    return iconData
}

// Hàm tạo biểu tượng trên system tray
func onReady() {
    systray.SetIcon(getIcon()) // Đặt biểu tượng
    systray.SetTooltip("Free-Wifi") // Tooltip

    // Tạo menu cho hệ thống
    menuQuit := systray.AddMenuItem("Thoát", "Thoát ứng dụng")

    // Chạy tác vụ lặp vô hạn trong goroutine
    go runAutoConnect()

    // Chờ người dùng thoát ứng dụng
    <-menuQuit.ClickedCh
    systray.Quit()
}

func LogError(err string) {
	if err == "" {
		return
	}

	// Open or create the error.txt file with append mode
	file, fileErr := os.OpenFile("error.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if fileErr != nil {
		// If there was an error opening the file, log to the default log
		log.Fatalf("error opening file: %v", fileErr)
	}
	defer file.Close()

	// Create a new logger that writes to the file
	logger := log.New(file, "", log.Ldate|log.Ltime)

	// Log the error message with a prefix
	logger.Printf("ERROR: %v\n", err)
	fmt.Printf("ERROR: %v\n", err)
	
	//exit
	quit()
}


func LogInfo(err string) {
	if err == "" {
		return
	}

	// Open or create the error.txt file with append mode
	file, fileErr := os.OpenFile("info.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if fileErr != nil {
		// If there was an error opening the file, log to the default log
		log.Fatalf("error opening file: %v", fileErr)
	}
	defer file.Close()

	// Create a new logger that writes to the file
	logger := log.New(file, "", log.Ldate|log.Ltime)

	// Log the error message with a prefix
	logger.Printf("INFO: %v\n", err)
	fmt.Printf("INFO: %v\n", err)
}

func quit() {
	os.Exit(1)
	systray.Quit()
}

func getPrivateKey(fragment1 string, fragment2 string) []byte {
	base64String := fragment1 + fragment2
	decodedBytes, _ := base64.StdEncoding.DecodeString(base64String)
	return []byte(string(decodedBytes))
}	

func convertToSeconds(timeStr string) int {
	// Define variables for minutes and seconds
	var minutes, seconds int

	// Use regular expression to extract minutes and seconds
	re := regexp.MustCompile(`(\d+)m(\d+)s`)
	match := re.FindStringSubmatch(timeStr)

	if len(match) > 2 {
		// Convert extracted minutes and seconds to integer
		minutes, _ = strconv.Atoi(match[1])
		seconds, _ = strconv.Atoi(match[2])
	}

	// Convert the time to total seconds
	totalSeconds := (minutes * 60) + seconds
	return totalSeconds
}


func runAutoConnect() {
	privateKey := getPrivateKey("YzRkN2UxMj","NmOTdiOGE2MA==")

	line1, _, err := readFirstTwoLines("key.txt")
	if err != nil {
		LogError("Cannot read key file!")
	}

	//fmt.Println("line1: ", line1)
	decodedBytes1, err := base64.StdEncoding.DecodeString(line1)
	if err != nil {	
		LogError("Wrong key!")
		quit()
	}

	message, err := AES_ECB_Decrypt(decodedBytes1, privateKey)
	if err != nil {	
		LogError("Wrong key!")
		quit()
	}
	parts := strings.Split(string(message), "/")
	if len(parts) != 2 {
		LogError("Wrong key!")
		quit()
	}
	address := parts[0]
	
	datetime := parts[1]
	fmt.Println("address: ", address)
	fmt.Println("expired: ", datetime)

	if address != getMacAddress()  {
		LogError("Cannot use key for this computer!")
		quit()
	}
	fmt.Println("Address is correct")

	if isExpired(datetime) {
		LogError("Key is expired!")
		quit()
	} else {
		fmt.Println("Time is not expired")
	}

	getStatusAndSleep()

	for {

		for {
			if isNetworkAvailable() {
				fmt.Println("Đang có kết nối internet")
			} else {
				fmt.Println("Mất kết nối internet")
				break
			}
			time.Sleep(1*time.Millisecond)
		}

		for {
			sendRequest()
			if(isNetworkAvailable()) {
				fmt.Println("Đã kết nối lại")
				break
			}
			time.Sleep(1*time.Millisecond)
		}

		if isExpired(string(datetime)) {
			LogError("Key is expired!")
			quit();
		} else {
			fmt.Println("Key còn hạn")
		}

		getStatusAndSleep()
	}
}


func loopGetStatus() (*http.Response) {
	for {
		resp, err := http.Get("http://rescue.wi-mesh.vn/status")
		if err == nil {
			return resp
		}
		LogInfo("Need to connect to Free Wi-Mesh-Secure")
		time.Sleep(2 * time.Second)
	}
}


func getStatusAndSleep() {
	resp := loopGetStatus()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response body: %v", err)
	}else {

		// Convert body to string
		bodyStr := string(body)

		// Define the regular expression to match "session-time-left" and its value
		re := regexp.MustCompile(`"session-time-left":"(.*?)"`)

		// Find the match
		match := re.FindStringSubmatch(bodyStr)

		if len(match) > 1 {
			if match[1] != "" {
				fmt.Println("session-time-left: ", match[1])
				time.Sleep(time.Duration(convertToSeconds(match[1]) - 1) * time.Second)
				fmt.Println("Awake!")
			}
		} else {
			fmt.Println("Sleep time not found! Awake!")
		}

	}
}