package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
)

const LineBreak = "\n"

func main() {
	username := "my-username"
	password := "my-password"

	// Generate key pair
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		fmt.Println("Gagal generate key pair:", err)
		return
	}

	// Encrypt username and password
	encryptedUsername, err := encrypt(publicKey, []byte(username))
	if err != nil {
		fmt.Println("Gagal mengenkripsi username:", err)
		return
	}

	encryptedPassword, err := encrypt(publicKey, []byte(password))
	if err != nil {
		fmt.Println("Gagal mengenkripsi password:", err)
		return
	}

	fmt.Println("================ encryption ================")
	fmt.Println("Username terenkripsi:", base64.StdEncoding.EncodeToString(encryptedUsername))
	fmt.Println("Password terenkripsi:", base64.StdEncoding.EncodeToString(encryptedPassword))
	fmt.Printf(LineBreak)

	// Decrypt username and password
	decryptedUsername, err := decrypt(privateKey, encryptedUsername)
	if err != nil {
		fmt.Println("Gagal mendekripsi username:", err)
		return
	}

	decryptedPassword, err := decrypt(privateKey, encryptedPassword)
	if err != nil {
		fmt.Println("Gagal mendekripsi password:", err)
		return
	}

	fmt.Println("================ decryption ================")
	fmt.Println("Username didekripsi:", string(decryptedUsername))
	fmt.Println("Password didekripsi:", string(decryptedPassword))
}

// Generate key pair
func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

// Encrypt data with public key
func encrypt(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Decrypt data with private key
func decrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
