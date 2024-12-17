package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Hàm xử lý request GET /key
func keyHandler(w http.ResponseWriter, r *http.Request) {
	// Lấy giá trị query parameters
	days := r.URL.Query().Get("days")
	address := r.URL.Query().Get("address")
	rawtext := r.URL.Query().Get("rawtext")

	encrypted := []byte("")
	result := ""
	err := error(nil)

	if(rawtext != "") {
		result = rawtext
	} else {
		// Kiểm tra xem có thiếu tham số không
		if days == "" || address == "" {
			http.Error(w, "Missing query parameters 'days' or 'address'", http.StatusBadRequest)
			return
		}

		// Kiểm tra days có phải là số không
		daysInt, err := strconv.Atoi(days)
		if err != nil {
			http.Error(w, "Invalid value for 'days'", http.StatusBadRequest)
			return
		}

		// Tính toán ngày mới (ngày hiện tại + 'days' ngày)
		currentTime := time.Now()
		newTime := currentTime.AddDate(0, 0, daysInt)

		// Tạo định dạng thời gian theo yêu cầu
		formattedDate := newTime.Format("2006-01-02 15:04:05")
		result = fmt.Sprintf("%s/%s", address, formattedDate)

	}

	encrypted, err = AES_ECB_Encrypt([]byte(result), []byte("c4d7e123f97b8a60"))	
	if err != nil {
		http.Error(w, "Error encrypting result", http.StatusBadRequest)
		return
	}

	//to base64
	encryptedResult := base64.StdEncoding.EncodeToString([]byte(encrypted))

	// Gửi kết quả về client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprint(encryptedResult)))
	w.Write([]byte("\n"))
	w.Write([]byte(fmt.Sprint(result)))
}

func decodeHandler(w http.ResponseWriter, r *http.Request) {
	// Lấy giá trị query parameters
	key := r.URL.Query().Get("key")

	//replace " " with "+"
	key =  strings.Replace(key, " ", "+", -1)

	// Kiểm tra xem có thiếu tham số không
	if key == "" {
		http.Error(w, "Missing query parameters 'key'", http.StatusBadRequest)
		return
	}
	
	keyByte, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		http.Error(w, "Error decrypting result", http.StatusBadRequest)
		return
	}

	decrypted, err := AES_ECB_Decrypt(keyByte, []byte("c4d7e123f97b8a60"))
	if err != nil {
		http.Error(w, "Error decrypting result", http.StatusBadRequest)
		return
	}

	// Gửi kết quả về client
	w.Header().Set("Content-Type", "application/json")
	if len(decrypted) == 0 {
		http.Error(w, "Error decrypting result", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(decrypted)
}




func main() {
	// Định nghĩa route và handler cho /key
	http.HandleFunc("/encode", keyHandler)
	http.HandleFunc("/decode", decodeHandler)

	// Bắt đầu server
	port := "8080"
	fmt.Printf("Server đang chạy trên cổng %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
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


func AES_ECB_Decrypt(ciphertext, key []byte) ([]byte, error) {

	defer func() {
		if r := recover(); r != nil {
		  	fmt.Println("Decryption error: panic")
		  	return 
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

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}