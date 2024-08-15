package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func main() {
	key := []byte("thisis32bitlongpassphraseimusing") 
	encodedSecret := []byte("Hello, World!")

	ciphertext, err := encrypt(encodedSecret, key)
	if err != nil {
		panic(err)
	}

	var inputCode string
	fmt.Print("Kodni kiriting: ")
	fmt.Scan(&inputCode)

	if inputCode != "salom" {
		fmt.Println("Xato kod!")
		playErrorSound()
		return
	}

	decodedText, err := decrypt(ciphertext, key)
	if err != nil {
		panic(err)
	}

	fmt.Println("Deshifrlangan matn:", string(decodedText))
}

func playErrorSound() {
	cmd := exec.Command("powershell", "-c", "[console]::beep(1000,5000)")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Ovozli signal yuborishda xato:", err)
	}
}