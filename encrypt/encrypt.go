package encrypt

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	var mac, datetime string
	fmt.Println("Enter mac address: ")
	fmt.Scanln(&mac)
	fmt.Println("Enter date time: ")
	fmt.Scanln(&datetime)

	// Encrypt mac address and datetime
	key := []byte("c4d7e123f97b8a60")
	ciphertext, err := AES_ECB_Encrypt([]byte(mac+"/"+datetime), key)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encode to base64
	encodedString := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println(encodedString)

	writeToFile("key.txt", encodedString)
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