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
	ipv4DeobfuscationCode = `
========= IPv4 Deobfuscation C Code ========

typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(\n"
	PCSTR			S,
	BOOLEAN			Strict,
	PCSTR*			Terminator,
	PVOID			Addr
);

BOOL Ipv4Deobfuscation(IN CHAR * Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {

	PBYTE		pBuffer		= NULL,
				TmpBuffer	= NULL;
	SIZE_T		sBuffSize	= NULL;
	PCSTR		Terminator	= NULL;
	NTSTATUS	STATUS		= NULL;

	// getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT(\"NTDLL\")), \"RtlIpv4StringToAddressA\");
	if (pRtlIpv4StringToAddressA == NULL) {
			printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError());
			return FALSE; 
	}
	// getting the real size of the shellcode (number of elements * 4 => original shellcode size)
	sBuffSize = NmbrOfElements * 4;
	// allocating mem, that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError());
		return FALSE;
	}
	// setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;


	// loop through all the addresses saved in Ipv4Array
	for (int i = 0; i < NmbrOfElements; i++) {
		// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
		if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			// if failed ...
			printf(\"[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X\\n\", Ipv4Array[i], STATUS);
			return FALSE;
		}

		// tmp buffer will be used to point to where to write next (in the newly allocated memory)
		TmpBuffer = (PBYTE)(TmpBuffer + 4);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

========= IPv4 Deobfuscation GO Code ========

import (
	"fmt"
	"github.com/google/uuid"
	"strconv"
	"strings"
)

func Ipv4Deobfuscation(ipv4Array []string) ([]byte, error) {
	var shellcode []byte

	for _, ipv4Str := range ipv4Array {
		// Split the IPv4 string into its components
		parts := strings.Split(ipv4Str, ".")
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid IPv4 format: %s", ipv4Str)
		}

		for _, part := range parts {
			// Convert each decimal part to a byte
			b, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("failed to parse IPv4 part [%s]: %v", part, err)
			}
			shellcode = append(shellcode, byte(b))
		}
	}

	return shellcode, nil
}
`

	ipv6DeobfuscationCode = `
========= IPv6 Deobfuscation C Code ========

typedef NTSTATUS (NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR			S,
	PCSTR*			Terminator,
	PVOID			Addr
);


BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {

	PBYTE		pBuffer		= NULL,
				TmpBuffer	= NULL;
	SIZE_T		sBuffSize	= NULL; 
	PCSTR		Terminator	= NULL;
	NTSTATUS	STATUS		= NULL;
	// getting RtlIpv6StringToAddressA  address from ntdll.dll
	fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT(\"NTDLL\")), \"RtlIpv6StringToAddressA\");
	if (pRtlIpv6StringToAddressA == NULL) {
			printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError());
			return FALSE;
	}
	// getting the real size of the shellcode (number of elements * 16 => original shellcode size)
	sBuffSize = NmbrOfElements * 16;
	// allocating mem, that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError());
		return FALSE;
	}
	// setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;


	// loop through all the addresses saved in Ipv6Array
	for (int i = 0; i < NmbrOfElements; i++) {
		// Ipv6Array[i] is a single ipv6 address from the array Ipv6Array
		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			// if failed ...
			printf(\"[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\\n\", Ipv6Array[i], STATUS);
			return FALSE;
		}

		// tmp buffer will be used to point to where to write next (in the newly allocated memory)
		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

========= IPv6 Deobfuscation GO Code ========

import (
	"fmt"
	"github.com/google/uuid"
	"strconv"
	"strings"
)

func Ipv6Deobfuscation(ipv6Array []string) ([]byte, error) {
	var shellcode []byte

	for _, ipv6Str := range ipv6Array {
		// Split the IPv6 string into its components
		parts := strings.Split(ipv6Str, ":")
		if len(parts) != 8 {
			return nil, fmt.Errorf("invalid IPv6 format: %s", ipv6Str)
		}

		for _, part := range parts {
			// Split each 4-character segment into two 2-character hex strings
			if len(part) != 4 {
				return nil, fmt.Errorf("invalid IPv6 segment length: %s", part)
			}

			for i := 0; i < len(part); i += 2 {
				hexByte := part[i : i+2]
				b, err := strconv.ParseUint(hexByte, 16, 8)
				if err != nil {
					return nil, fmt.Errorf("failed to parse IPv6 part [%s]: %v", hexByte, err)
				}
				shellcode = append(shellcode, byte(b))
			}
		}
	}

	return shellcode, nil
}
`

	macDeobfuscationCode = `
========= MAC Deobfuscation C Code ========

typedef NTSTATUS (NTAPI* fnRtlEthernetStringToAddressA)(
	PCSTR			S,
	PCSTR*			Terminator,
	PVOID			Addr
);


BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {

	PBYTE		pBuffer		= NULL,
				TmpBuffer	= NULL;
	SIZE_T		sBuffSize	= NULL;
	PCSTR		Terminator	= NULL;
	NTSTATUS	STATUS		= NULL;

	// getting fnRtlEthernetStringToAddressA  address from ntdll.dll
	fnRtlEthernetStringToAddressA  pRtlEthernetStringToAddressA  = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT(\"NTDLL\")), \"RtlEthernetStringToAddressA\");
	if (pRtlEthernetStringToAddressA  == NULL) {
			printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError());
			return FALSE;
	}
	// getting the real size of the shellcode (number of elements * 6 => original shellcode size)
	sBuffSize = NmbrOfElements * 6;
	// allocating mem, that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError());
		return FALSE;
	}
	// setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;


	// loop through all the addresses saved in MacArray
	for (int i = 0; i < NmbrOfElements; i++) {
		// MacArray[i] is a single mac address from the array MacArray
		if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {
			// if failed ...
			printf(\"[!] RtlEthernetStringToAddressA  Failed At [%s] With Error 0x%0.8X\\n\", MacArray[i], STATUS);
			return FALSE;
		}

		// tmp buffer will be used to point to where to write next (in the newly allocated memory)
		TmpBuffer = (PBYTE)(TmpBuffer + 6);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

========= MAC Deobfuscation GO Code ========

import (
		"fmt"
		"github.com/google/uuid"
		"strconv"
		"strings"
	)

func MacDeobfuscation(macArray []string) ([]byte, error) {
	var shellcode []byte

	for _, macStr := range macArray {
		// Split the MAC string into its components
		parts := strings.Split(macStr, "-")
		if len(parts) != 6 {
			return nil, fmt.Errorf("invalid MAC address format: %s", macStr)
		}

		for _, part := range parts {
			// Convert each hex pair to a byte
			b, err := strconv.ParseUint(part, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("failed to parse MAC part [%s]: %v", part, err)
			}
			shellcode = append(shellcode, byte(b))
		}
	}

	return shellcode, nil
}
`

	uuidDeobfuscationCode = `
========= UUID Deobfuscation C Code ========

	typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(
		RPC_CSTR	StringUuid,
		UUID*		Uuid
	);

	BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {\n\n
		PBYTE		pBuffer		= NULL,
					TmpBuffer	= NULL;
		SIZE_T		sBuffSize	= NULL;
		PCSTR		Terminator	= NULL;
		NTSTATUS	STATUS		= NULL;
		// getting UuidFromStringA   address from Rpcrt4.dll
		fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT(\"RPCRT4\")), \"UuidFromStringA\");
		if (pUuidFromStringA == NULL) {
				printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError());
				return FALSE;
		}
		// getting the real size of the shellcode (number of elements * 16 => original shellcode size)
		sBuffSize = NmbrOfElements * 16;
		// allocating mem, that will hold the deobfuscated shellcode
		pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
		if (pBuffer == NULL) {
			printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError());
			return FALSE;
		}
		// setting TmpBuffer to be equal to pBuffer
		TmpBuffer = pBuffer;


		// loop through all the addresses saved in Ipv6Array
		for (int i = 0; i < NmbrOfElements; i++) {
			// UuidArray[i] is a single UUid address from the array UuidArray
			if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
				// if failed ...
				printf(\"[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\\n\", UuidArray[i], STATUS);
				return FALSE;
			}

			// tmp buffer will be used to point to where to write next (in the newly allocated memory)
			TmpBuffer = (PBYTE)(TmpBuffer + 16);
		}

		*ppDAddress = pBuffer;
		*pDSize = sBuffSize;
		return TRUE;
}

========= UUID Deobfuscation GO Code ========

	import (
		"fmt"
		"github.com/google/uuid"
		"strconv"
		"strings"
	)
	
	func UuidDeobfuscation(uuidArray []string) ([]byte, error) {
	
		var shellcode []byte
	
		for _, uuidStr := range uuidArray {
			parsedUUID, err := uuid.Parse(uuidStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse UUID [%s]: %v", uuidStr, err)
			}
	
			// Extract the bytes from the UUID in reverse order
			bytes := parsedUUID[:]
	
			// Reconstruct the original order as per the GenerateUuid function logic
			originalOrder := []byte{
				bytes[3], bytes[2], bytes[1], bytes[0], // d, c, b, a
				bytes[5], bytes[4], bytes[7], bytes[6], // f, e, h, g
				bytes[8], bytes[9], bytes[10], bytes[11], // i, j, k, l
				bytes[12], bytes[13], bytes[14], bytes[15], // m, n, o, p
			}
	
			// Append to the shellcode
			shellcode = append(shellcode, originalOrder...)
		}
	
		return shellcode, nil
	}
`

	aesDecryptionCode = `
========= AES Deobfuscation C Code ========

	#include <Windows.h>
	#include <stdio.h>
	#include <bcrypt.h>
	#pragma comment(lib, \"Bcrypt.lib\")


	#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)
	#define KEYSIZE\t\t32
	#define IVSIZE\t\t16

	typedef struct _AES {
		PBYTE\tpPlainText;\t\t// base address of the plain text data
		DWORD\tdwPlainSize;\t\t// size of the plain text data\n
		PBYTE\tpCipherText;\t\t// base address of the encrypted data
		DWORD\tdwCipherSize;\t\t// size of it (this can change from dwPlainSize in case there was padding)\n
		PBYTE\tpKey;\t\t\t// the 32 byte key
		PBYTE\tpIv;\t\t\t// the 16 byte iv
	}AES, * PAES;

	// the real decryption implemantation
	BOOL InstallAesDecryption(PAES pAes) {

		BOOL				bSTATE = TRUE;

		BCRYPT_ALG_HANDLE		hAlgorithm = NULL;
		BCRYPT_KEY_HANDLE		hKeyHandle = NULL;

		ULONG				cbResult = NULL;
		DWORD				dwBlockSize = NULL;

		DWORD				cbKeyObject = NULL;
		PBYTE				pbKeyObject = NULL;

		PBYTE				pbPlainText = NULL;
		DWORD				cbPlainText = NULL;

		NTSTATUS			STATUS		= NULL;

		// intializing \"hAlgorithm\" as AES algorithm Handle
		STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(STATUS)) {
			printf(\"[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \\n\", STATUS);
			bSTATE = FALSE; goto _EndOfFunc;
		}
		// getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later
		STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0); 
		if (!NT_SUCCESS(STATUS)) {
			printf(\"[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \\n\", STATUS);
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)
		STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0); 
		if (!NT_SUCCESS(STATUS)) {
			printf(\"[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \\n\", STATUS); 
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// checking if block size is 16
		if (dwBlockSize != 16) {
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// allocating memory for the key object 
		pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject); 
		if (pbKeyObject == NULL) {
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// setting Block Cipher Mode to CBC (32 byte key and 16 byte Iv)
		STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0); 
		if (!NT_SUCCESS(STATUS)) {
			printf(\"[!] BCryptSetProperty Failed With Error: 0x%0.8X \\n\", STATUS); 
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// generating the key object from the aes key \"pAes->pKey\", the output will be saved in \"pbKeyObject\" of size \"cbKeyObject\" 
		STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0); 
		if (!NT_SUCCESS(STATUS)) {
			printf(\"[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \\n\", STATUS); 
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)
		STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING); 
		if (!NT_SUCCESS(STATUS)) {
			printf(\"[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \\n\", STATUS); 
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// allocating enough memory (of size cbPlainText)
		pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText); 
		if (pbPlainText == NULL) {
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// running BCryptDecrypt second time with \"pbPlainText\" as output buffer
		STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING); 
		if (!NT_SUCCESS(STATUS)) {
			printf(\"[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \\n\", STATUS); 
			bSTATE = FALSE; goto _EndOfFunc; 
		}
		// cleaning up
	_EndOfFunc:
		if (hKeyHandle) {
			BCryptDestroyKey(hKeyHandle); 
		}
		if (hAlgorithm) {
			BCryptCloseAlgorithmProvider(hAlgorithm, 0); 
		}
		if (pbKeyObject) {
			HeapFree(GetProcessHeap(), 0, pbKeyObject); 
		}
		if (pbPlainText != NULL && bSTATE) {
			// if everything went well, we save pbPlainText and cbPlainText
			pAes->pPlainText = pbPlainText; 
			pAes->dwPlainSize = cbPlainText; 
		}
		return bSTATE; 
	}


	// wrapper function for InstallAesDecryption that make things easier
	BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID * pPlainTextData, OUT DWORD * sPlainTextSize) {
		if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
			return FALSE;

		AES Aes = { 
			.pKey = pKey,
			.pIv = pIv,
			.pCipherText = pCipherTextData,
			.dwCipherSize = sCipherTextSize
		};

		if (!InstallAesDecryption(&Aes)) {
			return FALSE; 
		}

		*pPlainTextData = Aes.pPlainText; 
		*sPlainTextSize = Aes.dwPlainSize;

		return TRUE; 
	}

========= AES Deobfuscation GO Code ========
TODO
`
	rc4DecryptionCode = `
========= RC4 Deobfuscation C Code ========

#include <Windows.h>
#include <stdio.h>

// this is what SystemFunction032 function take as a parameter
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
);

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {
	
	// the return of SystemFunction032
	NTSTATUS	STATUS = NULL;
	
	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
			Img = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };
	
	
	// since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
	// and using its return as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA(\"Advapi32\"), \"SystemFunction032\");
	
	// if SystemFunction032 calls failed it will return non zero value
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
		printf(\"[!] SystemFunction032 FAILED With Error : 0x%0.8X\\n\", STATUS);
		return FALSE;
	}

	return TRUE;
}

========= RC4 Deobfuscation GO Code ========
TODO
`
)
