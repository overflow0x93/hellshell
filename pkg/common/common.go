package common

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"time"
)

// Constants to help identify user input
const (
	UUIDFuscation = 0x444
	AESEncryption = 0x555
	RC4Encryption = 0x666
	IPv6Fuscation = 0x111
	IPv4Fuscation = 0x222
	MACFuscation  = 0x333
	RC4KeySize    = 16
	AESKeySize    = 32
	AESIVSize     = 16
)

// ReadPayloadFile reads a file from disk
func ReadPayloadFile(fileInput string) ([]byte, error) {
	data, err := os.ReadFile(fileInput)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// WritePayloadFile writes a file to disk
func WritePayloadFile(fileInput string, payloadData []byte) error {
	return os.WriteFile(fileInput, payloadData, 0644)
}

// PrintDecodeFunctionality prints the decryption/deobfuscation function as a string to the screen
func PrintDecodeFunctionality(decodeType int) {
	switch decodeType {
	case UUIDFuscation:
		fmt.Println("UUID Fuscation")
	case AESEncryption:
		fmt.Println("AES Encryption")
	case RC4Encryption:
		fmt.Println("RC4 Encryption")
	case IPv6Fuscation:
		fmt.Println("IPv6 Fuscation")
	case IPv4Fuscation:
		fmt.Println("IPv4 Fuscation")
	case MACFuscation:
		fmt.Println("MAC Fuscation")
	default:
		fmt.Println("Unknown type")
	}
}

// GenerateRandomBytes generates random bytes of the given size
func GenerateRandomBytes(size int) []byte {
	rand.Seed(time.Now().UnixNano())
	bytes := make([]byte, size)
	rand.Read(bytes)
	return bytes
}

// PrintHexData prints the input buffer as a hex char array (C syntax)
func PrintHexData(name string, data []byte) {
	fmt.Printf("%s: %s\n", name, hex.EncodeToString(data))
}

// SimpleEncryption is a wrapper function for AES encryption that makes things easier
func SimpleEncryption(plainTextData, key, iv []byte) ([]byte, error) {
	// This function would implement AES encryption logic, returning ciphertext and any error encountered
	// For example:
	// return aesEncrypt(plainTextData, key, iv)
	return nil, nil
}

// Rc4EncryptionViSystemFunc032 performs the RC4 encryption
func Rc4EncryptionViSystemFunc032(rc4Key, payloadData []byte) ([]byte, error) {
	// This function would implement RC4 encryption logic, returning ciphertext and any error encountered
	// For example:
	// return rc4Encrypt(rc4Key, payloadData)
	return nil, nil
}

// GenerateUuidOutput generates the UUID output representation of the shellcode
func GenerateUuidOutput(shellcode []byte) error {
	// This function would implement the UUID generation logic
	return nil
}

// GenerateMacOutput generates the MAC output representation of the shellcode
func GenerateMacOutput(shellcode []byte) error {
	// This function would implement the MAC generation logic
	return nil
}

// GenerateIpv6Output generates the IPv6 output representation of the shellcode
func GenerateIpv6Output(shellcode []byte) error {
	// This function would implement the IPv6 generation logic
	return nil
}

// GenerateIpv4Output generates the IPv4 output representation of the shellcode
func GenerateIpv4Output(shellcode []byte) error {
	// This function would implement the IPv4 generation logic
	return nil
}
