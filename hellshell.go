package main

import (
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
			pAppendedPayload, err = common.AppendInputPayload(6, pPayloadInput)
			if err != nil {
				fmt.Println("Error appending payload:", err)
				os.Exit(-1)
			}
			dwAppendedSize = len(pAppendedPayload)
		}

		output := obfuscation.GenerateMacOutput(pAppendedPayload)
		fmt.Println("========= PAYLOAD ========\n")
		dwType = common.MACFuscation
		for i := 0; i < len(output); i += 4 {
			if i+4 > len(output) {
				if i+3 < len(output) {
					fmt.Printf("\"%s\",\t\"%s\",\t\"%s\"\n\n", output[i], output[i+1], output[i+2])
				} else if i+2 < len(output) {
					fmt.Printf("\"%s\",\t\"%s\"\n\n", output[i], output[i+1])
				} else if i+1 < len(output) {
					fmt.Printf("\"%s\"\n\n", output[i])
				}
				break
			} else if i+4 == len(output) {
				fmt.Printf("\"%s\",\t\"%s\",\t\"%s\",\t\"%s\"\n\n", output[i], output[i+1], output[i+2], output[i+3])
			} else {
				fmt.Printf("\"%s\",\t\"%s\",\t\"%s\",\t\"%s\",\n", output[i], output[i+1], output[i+2], output[i+3])
			}
		}
		deob, err := deobfuscation.MacDeobfuscation(output)
		if err != nil {
			fmt.Println("Error decoding MAC payload:", err)
		} else {
			fmt.Println("========= Sanity Deobfuscation ========\n")
			fmt.Println(string(deob))
		}

	case "ipv4":
		if len(pPayloadInput)%4 != 0 {
			pAppendedPayload, err = common.AppendInputPayload(4, pPayloadInput)
			if err != nil {
				fmt.Println("Error appending payload:", err)
				os.Exit(-1)
			}
			dwAppendedSize = len(pAppendedPayload)
		}

		output := obfuscation.GenerateIpv4Output(pAppendedPayload)
		fmt.Println("========= PAYLOAD ========\n")
		dwType = common.IPv4Fuscation
		for i := 0; i < len(output); i += 4 {
			if i+4 > len(output) {
				if i+3 < len(output) {
					if len(output[i]) < 13 {
						fmt.Printf("\"%s\",\t\t", output[i])
					} else {
						fmt.Printf("\"%s\",\t", output[i])
					}
					if len(output[i+1]) < 13 {
						fmt.Printf("\"%s\",\t\t", output[i+1])
					} else {
						fmt.Printf("\"%s\",\t", output[i+1])
					}
					fmt.Printf("\"%s\"\n\n", output[i+2])
				} else if i+2 < len(output) {
					if len(output[i]) < 13 {
						fmt.Printf("\"%s\",\t\t", output[i])
					} else {
						fmt.Printf("\"%s\",\t", output[i])
					}
					fmt.Printf("\"%s\"\n\n", output[i+1])
				} else if i+1 < len(output) {
					fmt.Printf("\"%s\"\n\n", output[i])
				}
				break
			} else if i+4 == len(output) {
				if len(output[i]) < 13 {
					fmt.Printf("\"%s\",\t\t", output[i])
				} else {
					fmt.Printf("\"%s\",\t", output[i])
				}
				if len(output[i+1]) < 13 {
					fmt.Printf("\"%s\",\t\t", output[i+1])
				} else {
					fmt.Printf("\"%s\",\t", output[i+1])
				}
				if len(output[i+2]) < 13 {
					fmt.Printf("\"%s\",\t\t", output[i+2])
				} else {
					fmt.Printf("\"%s\",\t", output[i+2])
				}
				fmt.Printf("\"%s\"\n\n", output[i+3])
			} else {
				if len(output[i]) < 13 {
					fmt.Printf("\"%s\",\t\t", output[i])
				} else {
					fmt.Printf("\"%s\",\t", output[i])
				}
				if len(output[i+1]) < 13 {
					fmt.Printf("\"%s\",\t\t", output[i+1])
				} else {
					fmt.Printf("\"%s\",\t", output[i+1])
				}
				if len(output[i+2]) < 13 {
					fmt.Printf("\"%s\",\t\t", output[i+2])
				} else {
					fmt.Printf("\"%s\",\t", output[i+2])
				}
				fmt.Printf("\"%s\",\n", output[i+3])
			}

		}

		deob, err := deobfuscation.Ipv4Deobfuscation(output)
		if err != nil {
			fmt.Println("Error decoding IPv4 payload:", err)
		} else {
			fmt.Println("========= Sanity Deobfuscation ========\n")
			fmt.Println(string(deob))
		}

	case "ipv6":
		if len(pPayloadInput)%16 != 0 {
			pAppendedPayload, err = common.AppendInputPayload(16, pPayloadInput)
			if err != nil {
				fmt.Println("Error appending payload:", err)
				os.Exit(-1)
			}
			dwAppendedSize = len(pAppendedPayload)
		}

		output := obfuscation.GenerateIpv6Output(pAppendedPayload)
		fmt.Println("========= PAYLOAD ========\n")
		dwType = common.IPv6Fuscation
		for i := 0; i < len(output); i += 2 {
			if i+2 > len(output) {
				fmt.Printf("\"%s\"\n\n", output[i])
			} else if i+2 == len(output) {
				fmt.Printf("\"%s\",\t\"%s\"\n\n", output[i], output[i+1])
			} else {
				fmt.Printf("\"%s\",\t\"%s\",\n", output[i], output[i+1])
			}
		}
		deob, err := deobfuscation.Ipv6Deobfuscation(output)
		if err != nil {
			fmt.Println("Error decoding IPv6 payload:", err)
		} else {
			fmt.Println("========= Sanity Deobfuscation ========\n")
			fmt.Println(string(deob))
		}

	case "uuid":
		if len(pPayloadInput)%16 != 0 {
			pAppendedPayload, err = common.AppendInputPayload(16, pPayloadInput)
			if err != nil {
				fmt.Println("Error appending payload:", err)
				os.Exit(-1)
			}
			dwAppendedSize = len(pAppendedPayload)
		}
		output := obfuscation.GenerateUuidOutput(pAppendedPayload)
		fmt.Println("========= PAYLOAD ========\n")
		dwType = common.UUIDFuscation
		for i := 0; i < len(output); i += 2 {
			if i+2 > len(output) {
				fmt.Printf("\"%s\"\n\n", output[i])
			} else if i+2 == len(output) {
				fmt.Printf("\"%s\",\t\"%s\"\n\n", output[i], output[i+1])
			} else {
				fmt.Printf("\"%s\",\t\"%s\",\n", output[i], output[i+1])
			}
		}
		deob, err := deobfuscation.UuidDeobfuscation(output) //, &ppDAddress, &pDSize)
		if err != nil {
			fmt.Println("Error decoding UUID payload:", err)
		} else {
			fmt.Println("========= Sanity Deobfuscation ========\n")
			fmt.Println(string(deob))
		}

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
