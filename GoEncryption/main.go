package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {

	

	mac, datetime, err := readFirstTwoLines("info.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	
	mac = convertMAC(mac)

	// Encrypt mac address and datetime
	key := []byte("c4d7e123f97b8a60")
	ciphertext, err := AES_ECB_Encrypt([]byte(mac+"/"+datetime), key)
	if err != nil {
		fmt.Println(err)
		return
	}
	
	// Encode to base64
	encodedString := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println(mac+"/"+datetime)
	fmt.Println(encodedString)
	
	writeToFile("key.txt", encodedString)
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



func writeToFile(filename, data string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(data)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func convertMAC(mac string) string {
	// Loại bỏ dấu '-' và chuyển thành chữ thường
	mac = strings.ReplaceAll(mac, "-", ":")
	return strings.ToLower(mac)
}


func AES_ECB_Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Padding plaintext to be a multiple of block size
	plaintext = PKCS7Padding(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))

	// Encrypt each block
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], plaintext[i:i+block.BlockSize()])
	}

	return ciphertext, nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}