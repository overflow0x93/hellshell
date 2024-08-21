package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/overflow0x93/hellshell/pkg/common"
	"github.com/overflow0x93/hellshell/pkg/obfuscation"
	"github.com/overflow0x93/hellshell/pkg/stringfunctions"
	"math/rand"
	"os"
	"time"
)

// Array of supported output (supported input argv[2] encryption/obfuscation type)
var SupportedOutput = []string{"mac", "ipv4", "ipv6", "uuid", "aes", "rc4"}

// AppendInputPayload appends payload to make its size a multiple of the given value.
func AppendInputPayload(multipleOf int, payload []byte) ([]byte, error) {
	appendSize := len(payload) + multipleOf - (len(payload) % multipleOf)
	appendedPayload := bytes.Repeat([]byte{0x90}, appendSize)
	copy(appendedPayload, payload)
	return appendedPayload, nil
}

// PrintHelp prints the help message.
func PrintHelp(argv0 string) int {
	fmt.Println("\t\t\t ###########################################################")
	fmt.Println("\t\t\t # HellShell - Designed By MalDevAcademy @NUL0x4C | @mrd0x #")
	fmt.Println("\t\t\t ###########################################################\n")
	fmt.Printf("[!] Usage: %s <Input Payload FileName> <Enc/Obf *Option*> \n", argv0)
	fmt.Println("[i] Options Can Be : ")
	fmt.Println("\t1.>>> \"mac\"     ::: Output The Shellcode As A Array Of Mac Addresses  [FC-48-83-E4-F0-E8]")
	fmt.Println("\t2.>>> \"ipv4\"    ::: Output The Shellcode As A Array Of Ipv4 Addresses [252.72.131.228]")
	fmt.Println("\t3.>>> \"ipv6\"    ::: Output The Shellcode As A Array Of Ipv6 Addresses [FC48:83E4:F0E8:C000:0000:4151:4150:5251]")
	fmt.Println("\t4.>>> \"uuid\"    ::: Output The Shellcode As A Array Of UUid Strings   [FC4883E4-F0E8-C000-0000-415141505251]")
	fmt.Println("\t5.>>> \"aes\"     ::: Output The Shellcode As A Array Of Aes Encrypted Shellcode With Random Key And Iv")
	fmt.Println("\t6.>>> \"rc4\"     ::: Output The Shellcode As A Array Of Rc4 Encrypted Shellcode With Random Key")
	fmt.Println("\n\n[i] ")
	return -1
}

func main() {
	// Data to help us in dealing with user's input
	var dwType int
	bSupported := false

	// Variables used for holding data on the read payload
	var pPayloadInput []byte
	var dwPayloadSize int
	_ = dwPayloadSize
	// Just in case we needed to append our input payload:
	var pAppendedPayload []byte
	var dwAppendedSize int
	_ = dwAppendedSize
	// Variables used for holding data on the encrypted payload (aes/rc4)
	var pCipherText []byte
	var dwCipherSize int
	_ = dwCipherSize
	// Checking input
	if len(os.Args) != 3 {
		os.Exit(PrintHelp(os.Args[0]))
	}

	// Verifying input
	for _, output := range SupportedOutput {
		if os.Args[2] == output {
			bSupported = true
			break
		}
	}

	if !bSupported {
		fmt.Printf("<<<!>>> \"%s\" Is not Valid Input <<<!>>>\n", os.Args[2])
		os.Exit(PrintHelp(os.Args[0]))
	}

	// Reading input payload
	var err error
	pPayloadInput, err = ReadPayloadFile(os.Args[1])
	if err != nil {
		fmt.Println("Error reading payload file:", err)
		os.Exit(-1)
	}

	// Initialize the possible append variables
	pAppendedPayload = pPayloadInput
	dwAppendedSize = len(pPayloadInput)

	switch os.Args[2] {
	case "mac":
		if len(pPayloadInput)%6 != 0 {
			pAppendedPayload, err = AppendInputPayload(6, pPayloadInput)
			if err != nil {
				fmt.Println("Error appending payload:", err)
				os.Exit(-1)
			}
			dwAppendedSize = len(pAppendedPayload)
		}

		obfuscation.GenerateMacOutput(pAppendedPayload)
		/*
			err = GenerateMacOutput(pAppendedPayload)
			if err != nil {
				fmt.Println("Error generating MAC output:", err)
				os.Exit(-1)
			}*/

		dwType = common.MACFuscation

	case "ipv4":
		if len(pPayloadInput)%4 != 0 {
			pAppendedPayload, err = AppendInputPayload(4, pPayloadInput)
			if err != nil {
				fmt.Println("Error appending payload:", err)
				os.Exit(-1)
			}
			dwAppendedSize = len(pAppendedPayload)
		}

		obfuscation.GenerateIpv4Output(pAppendedPayload)
		/*
			err = GenerateIpv4Output(pAppendedPayload)
			if err != nil {
				fmt.Println("Error generating IPv4 output:", err)
				os.Exit(-1)
			}*/

		dwType = common.IPv4Fuscation

	case "ipv6":
		if len(pPayloadInput)%16 != 0 {
			pAppendedPayload, err = AppendInputPayload(16, pPayloadInput)
			if err != nil {
				fmt.Println("Error appending payload:", err)
				os.Exit(-1)
			}
			dwAppendedSize = len(pAppendedPayload)
		}

		obfuscation.GenerateIpv6Output(pAppendedPayload)
		/*
			err = GenerateIpv6Output(pAppendedPayload)
			if err != nil {
				fmt.Println("Error generating IPv6 output:", err)
				os.Exit(-1)
			}*/

		dwType = common.IPv6Fuscation

	case "uuid":
		if len(pPayloadInput)%16 != 0 {
			pAppendedPayload, err = AppendInputPayload(16, pPayloadInput)
			if err != nil {
				fmt.Println("Error appending payload:", err)
				os.Exit(-1)
			}
			dwAppendedSize = len(pAppendedPayload)
		}
		/*
			err = GenerateUuidOutput(pAppendedPayload)
			if err != nil {
				fmt.Println("Error generating UUID output:", err)
				os.Exit(-1)
			}*/
		obfuscation.GenerateUuidOutput(pAppendedPayload)

		dwType = common.UUIDFuscation

	case "aes":
		key := GenerateRandomBytes(common.AESKeySize)
		iv := GenerateRandomBytes(common.AESIVSize)
		keyCopy := make([]byte, len(key))
		ivCopy := make([]byte, len(iv))
		copy(keyCopy, key)
		copy(ivCopy, iv)

		common.SimpleEncryption(pPayloadInput, key, iv)
		/*
			pCipherText, err = SimpleEncryption(pPayloadInput, key, iv)
			if err != nil {
				fmt.Println("Error during AES encryption:", err)
				os.Exit(-1)
			}*/
		dwCipherSize = len(pCipherText)

		stringfunctions.PrintDecodeFunctionality(common.AESEncryption)
		PrintHexData("AesCipherText", pCipherText)
		PrintHexData("AesKey", keyCopy)
		PrintHexData("AesIv", ivCopy)

	case "rc4":
		key := GenerateRandomBytes(common.RC4KeySize)
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)

		common.Rc4EncryptionViSystemFunc032(key, pPayloadInput)
		/*
			err = Rc4EncryptionViSystemFunc032(key, pPayloadInput)
			if err != nil {
				fmt.Println("Error during RC4 encryption:", err)
				os.Exit(-1)
			}*/

		stringfunctions.PrintDecodeFunctionality(common.RC4Encryption)
		PrintHexData("Rc4CipherText", pPayloadInput)
		PrintHexData("Rc4Key", keyCopy)
	}

	fmt.Println("\n\n")

	if dwType != 0 {
		stringfunctions.PrintDecodeFunctionality(dwType)
	}

	os.Exit(0)
}

func ReadPayloadFile(fileInput string) ([]byte, error) {
	data, err := os.ReadFile(fileInput)
	//if err != nil {
	//	return nil, errors.Wrap(err, "failed to read file")
	//}
	if err != nil {
		return nil, err //, errors.Wrap(err, "failed to read file")
	}
	return data, nil
}

func GenerateRandomBytes(size int) []byte {
	rand.Seed(time.Now().UnixNano())
	bytes := make([]byte, size)
	rand.Read(bytes)
	return bytes
}

func PrintHexData(name string, data []byte) {
	fmt.Printf("%s: %s\n", name, hex.EncodeToString(data))
}

/*
func GenerateMacOutput(shellcode []byte) error {
	// Implement the logic to generate the MAC output
	return nil
}

func GenerateIpv4Output(shellcode []byte) error {
	// Implement the logic to generate the IPv4 output
	return nil
}

func GenerateIpv6Output(shellcode []byte) error {
	// Implement the logic to generate the IPv6 output
	return nil
}

func GenerateUuidOutput(shellcode []byte) error {
	// Implement the logic to generate the UUID output
	return nil
}

func SimpleEncryption(plainText, key, iv []byte) ([]byte, error) {
	// Implement the logic for AES encryption
	return nil, nil
}

func Rc4EncryptionViSystemFunc032(key, payload []byte) error {
	// Implement the logic for RC4 encryption
	return nil
}
*/
/*
func PrintDecodeFunctionality(decodeType int) {
	switch decodeType {
	case common.UUIDFuscation:
		fmt.Println("UUID Fuscation")
	case common.AESEncryption:
		fmt.Println("AES Encryption")
	case common.RC4Encryption:
		fmt.Println("RC4 Encryption")
	case common.IPv6Fuscation:
		fmt.Println("IPv6 Fuscation")
	case common.IPv4Fuscation:
		fmt.Println("IPv4 Fuscation")
	case common.MACFuscation:
		fmt.Println("MAC Fuscation")
	default:
		fmt.Println("Unknown type")
	}
}
*/
