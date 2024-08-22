package deobfuscation

import (
	"fmt"
	"github.com/google/uuid"
	"strconv"
	"strings"
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
