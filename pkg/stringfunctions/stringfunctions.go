package stringfunctions

import (
	"fmt"
	"github.com/overflow0x93/hellshell/pkg/common"
)

// Function to print the deobfuscation functionality code for a given type.
func PrintDecodeFunctionality(typeCode int) {
	if typeCode == 0 {
		fmt.Println("[!] Missing Input Type (StringFunctions:362)")
		return
	}

	switch typeCode {
	case common.IPv4Fuscation:
		fmt.Println(ipv4DeobfuscationCode)
	case common.IPv6Fuscation:
		fmt.Println(ipv6DeobfuscationCode)
	case common.MACFuscation:
		fmt.Println(macDeobfuscationCode)
	case common.UUIDFuscation:
		fmt.Println(uuidDeobfuscationCode)
	case common.AESEncryption:
		fmt.Println(aesDecryptionCode)
	case common.RC4Encryption:
		fmt.Println(rc4DecryptionCode)
	default:
		fmt.Printf("[!] Unsupported Type Entered : 0x%0.8X\n", typeCode)
	}
}

// Code strings for deobfuscation functions.
const (
	ipv4DeobfuscationCode = `// Ipv4Deobfuscation deobfuscates an array of IPv4 addresses.
func Ipv4Deobfuscation(ipv4Array []*byte, numberOfElements int, ppDAddress **byte, pDSize *int) bool {
	var (
		pBuffer     *byte
		tmpBuffer   *byte
		sBuffSize   int
		terminator  *byte
		status      uint32
		pRtlIpv4    fnRtlIpv4StringToAddressA
		kernel32    = syscall.MustLoadDLL("ntdll.dll")
		procAddress = kernel32.MustFindProc("RtlIpv4StringToAddressA")
	)
	pRtlIpv4 = procAddress.Addr().(*fnRtlIpv4StringToAddressA)

	if pRtlIpv4 == nil {
		fmt.Printf("[!] GetProcAddress Failed With Error : %d\n", syscall.GetLastError())
		return false
	}

	sBuffSize = numberOfElements * 4
	pBuffer = (*byte)(syscall.HeapAlloc(syscall.GetProcessHeap(), 0, uintptr(sBuffSize)))
	if pBuffer == nil {
		fmt.Printf("[!] HeapAlloc Failed With Error : %d\n", syscall.GetLastError())
		return false
	}
	tmpBuffer = pBuffer

	for i := 0; i < numberOfElements; i++ {
		status = pRtlIpv4(
			(*byte)(ipv4Array[i]),
			false,
			&terminator,
			unsafe.Pointer(tmpBuffer),
		)
		if status != 0 {
			fmt.Printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X\n", string(ipv4Array[i]), status)
			return false
		}
		tmpBuffer = (*byte)(unsafe.Pointer(tmpBuffer) + 4)
	}

	*ppDAddress = pBuffer
	*pDSize = sBuffSize
	return true
}
`

	ipv6DeobfuscationCode = `// Ipv6Deobfuscation deobfuscates an array of IPv6 addresses.
func Ipv6Deobfuscation(ipv6Array []*byte, numberOfElements int, ppDAddress **byte, pDSize *int) bool {
	var (
		pBuffer     *byte
		tmpBuffer   *byte
		sBuffSize   int
		terminator  *byte
		status      uint32
		pRtlIpv6    fnRtlIpv6StringToAddressA
		kernel32    = syscall.MustLoadDLL("ntdll.dll")
		procAddress = kernel32.MustFindProc("RtlIpv6StringToAddressA")
	)
	pRtlIpv6 = procAddress.Addr().(*fnRtlIpv6StringToAddressA)

	if pRtlIpv6 == nil {
		fmt.Printf("[!] GetProcAddress Failed With Error : %d\n", syscall.GetLastError())
		return false
	}

	sBuffSize = numberOfElements * 16
	pBuffer = (*byte)(syscall.HeapAlloc(syscall.GetProcessHeap(), 0, uintptr(sBuffSize)))
	if pBuffer == nil {
		fmt.Printf("[!] HeapAlloc Failed With Error : %d\n", syscall.GetLastError())
		return false
	}
	tmpBuffer = pBuffer

	for i := 0; i < numberOfElements; i++ {
		status = pRtlIpv6(
			(*byte)(ipv6Array[i]),
			&terminator,
			unsafe.Pointer(tmpBuffer),
		)
		if status != 0 {
			fmt.Printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", string(ipv6Array[i]), status)
			return false
		}
		tmpBuffer = (*byte)(unsafe.Pointer(tmpBuffer) + 16)
	}

	*ppDAddress = pBuffer
	*pDSize = sBuffSize
	return true
}
`

	macDeobfuscationCode = `// MacDeobfuscation deobfuscates an array of MAC addresses.
func MacDeobfuscation(macArray []*byte, numberOfElements int, ppDAddress **byte, pDSize *int) bool {
	var (
		pBuffer     *byte
		tmpBuffer   *byte
		sBuffSize   int
		terminator  *byte
		status      uint32
		pRtlMac    fnRtlEthernetStringToAddressA
		kernel32    = syscall.MustLoadDLL("ntdll.dll")
		procAddress = kernel32.MustFindProc("RtlEthernetStringToAddressA")
	)
	pRtlMac = procAddress.Addr().(*fnRtlEthernetStringToAddressA)

	if pRtlMac == nil {
		fmt.Printf("[!] GetProcAddress Failed With Error : %d\n", syscall.GetLastError())
		return false
	}

	sBuffSize = numberOfElements * 6
	pBuffer = (*byte)(syscall.HeapAlloc(syscall.GetProcessHeap(), 0, uintptr(sBuffSize)))
	if pBuffer == nil {
		fmt.Printf("[!] HeapAlloc Failed With Error : %d\n", syscall.GetLastError())
		return false
	}
	tmpBuffer = pBuffer

	for i := 0; i < numberOfElements; i++ {
		status = pRtlMac(
			(*byte)(macArray[i]),
			&terminator,
			unsafe.Pointer(tmpBuffer),
		)
		if status != 0 {
			fmt.Printf("[!] RtlEthernetStringToAddressA Failed At [%s] With Error 0x%0.8X\n", string(macArray[i]), status)
			return false
		}
		tmpBuffer = (*byte)(unsafe.Pointer(tmpBuffer) + 6)
	}

	*ppDAddress = pBuffer
	*pDSize = sBuffSize
	return true
}
`

	uuidDeobfuscationCode = `// UuidDeobfuscation deobfuscates an array of UUIDs.
func UuidDeobfuscation(uuidArray []*byte, numberOfElements int, ppDAddress **byte, pDSize *int) bool {
	var (
		pBuffer     *byte
		tmpBuffer   *byte
		sBuffSize   int
		status      uint32
		pUuidString fnUuidFromStringA
		rpcrt4      = syscall.MustLoadDLL("rpcrt4.dll")
		procAddress = rpcrt4.MustFindProc("UuidFromStringA")
	)
	pUuidString = procAddress.Addr().(*fnUuidFromStringA)

	if pUuidString == nil {
		fmt.Printf("[!] GetProcAddress Failed With Error : %d\n", syscall.GetLastError())
		return false
	}

	sBuffSize = numberOfElements * 16
	pBuffer = (*byte)(syscall.HeapAlloc(syscall.GetProcessHeap(), 0, uintptr(sBuffSize)))
	if pBuffer == nil {
		fmt.Printf("[!] HeapAlloc Failed With Error : %d\n", syscall.GetLastError())
		return false
	}
	tmpBuffer = pBuffer

	for i := 0; i < numberOfElements; i++ {
		status = pUuidString(
			(*byte)(uuidArray[i]),
			(*syscall.UUID)(unsafe.Pointer(tmpBuffer)),
		)
		if status != 0 {
			fmt.Printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X\n", string(uuidArray[i]), status)
			return false
		}
		tmpBuffer = (*byte)(unsafe.Pointer(tmpBuffer) + 16)
	}

	*ppDAddress = pBuffer
	*pDSize = sBuffSize
	return true
}
`

	aesDecryptionCode = `// AesDecryption decrypts data using AES.
// TODO: Implement the AES decryption functionality.
func AesDecryption(encryptedData []byte, key []byte, iv []byte, ppDAddress **byte, pDSize *int) bool {
	// ...
	return true
}
`

	rc4DecryptionCode = `// Rc4Decryption decrypts data using RC4.
// TODO: Implement the RC4 decryption functionality.
func Rc4Decryption(encryptedData []byte, key []byte, ppDAddress **byte, pDSize *int) bool {
	// ...
	return true
}
`
)
