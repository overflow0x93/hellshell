package obfuscation

import (
	"fmt"
)

func GenerateUuid(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p int) string {
	output0 := fmt.Sprintf("%02X%02X%02X%02X", d, c, b, a)
	output1 := fmt.Sprintf("%02X%02X-%02X%02X", f, e, h, g)
	output2 := fmt.Sprintf("%02X%02X-%02X%02X", i, j, k, l)
	output3 := fmt.Sprintf("%02X%02X%02X%02X", m, n, o, p)
	return fmt.Sprintf("%s-%s-%s%s", output0, output1, output2, output3)
}

func GenerateUuidOutput(shellcode []byte) []string {
	if len(shellcode)%16 != 0 {
		return nil
	}
	var Output []string
	//fmt.Println("var UuidArray = []string{")
	for i := 0; i < len(shellcode); i += 16 {
		uuid := GenerateUuid(
			int(shellcode[i]), int(shellcode[i+1]), int(shellcode[i+2]), int(shellcode[i+3]),
			int(shellcode[i+4]), int(shellcode[i+5]), int(shellcode[i+6]), int(shellcode[i+7]),
			int(shellcode[i+8]), int(shellcode[i+9]), int(shellcode[i+10]), int(shellcode[i+11]),
			int(shellcode[i+12]), int(shellcode[i+13]), int(shellcode[i+14]), int(shellcode[i+15]),
		)
		if i+16 < len(shellcode) {
			//fmt.Printf("\"%s\", ", uuid)
		} else {
			//fmt.Printf("\"%s\"", uuid)
		}
		if (i/16)%3 == 2 {
			//fmt.Println()
		}
		Output = append(Output, uuid)
	}
	return Output
}

func GenerateMac(a, b, c, d, e, f int) string {
	return fmt.Sprintf("%02X-%02X-%02X-%02X-%02X-%02X", a, b, c, d, e, f)
}

func GenerateMacOutput(shellcode []byte) []string {
	if len(shellcode)%6 != 0 {
		return nil
	}
	var Output []string
	for i := 0; i < len(shellcode); i += 6 {
		mac := GenerateMac(
			int(shellcode[i]), int(shellcode[i+1]), int(shellcode[i+2]), int(shellcode[i+3]),
			int(shellcode[i+4]), int(shellcode[i+5]),
		)
		if i+6 < len(shellcode) {
			//fmt.Printf("\"%s\", ", mac)
		} else {
			//fmt.Printf("\"%s\"", mac)
		}
		if (i/6)%6 == 5 {
			//fmt.Println()
		}
		Output = append(Output, mac)
	}
	return Output
}

func GenerateIpv6(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p int) string {
	output0 := fmt.Sprintf("%02X%02X:%02X%02X", a, b, c, d)
	output1 := fmt.Sprintf("%02X%02X:%02X%02X", e, f, g, h)
	output2 := fmt.Sprintf("%02X%02X:%02X%02X", i, j, k, l)
	output3 := fmt.Sprintf("%02X%02X:%02X%02X", m, n, o, p)
	return fmt.Sprintf("%s:%s:%s:%s", output0, output1, output2, output3)
}

func GenerateIpv6Output(shellcode []byte) []string {
	if len(shellcode)%16 != 0 {
		return nil
	}
	var Output []string
	//fmt.Println("var Ipv6Array = []string{")
	for i := 0; i < len(shellcode); i += 16 {
		ipv6 := GenerateIpv6(
			int(shellcode[i]), int(shellcode[i+1]), int(shellcode[i+2]), int(shellcode[i+3]),
			int(shellcode[i+4]), int(shellcode[i+5]), int(shellcode[i+6]), int(shellcode[i+7]),
			int(shellcode[i+8]), int(shellcode[i+9]), int(shellcode[i+10]), int(shellcode[i+11]),
			int(shellcode[i+12]), int(shellcode[i+13]), int(shellcode[i+14]), int(shellcode[i+15]),
		)
		if i+16 < len(shellcode) {
			//fmt.Printf("\"%s\", ", ipv6)
		} else {
			//fmt.Printf("\"%s\"", ipv6)
		}
		if (i/16)%3 == 2 {
			//fmt.Println()
		}
		Output = append(Output, ipv6)
	}
	return Output
}

func GenerateIpv4(a, b, c, d int) string {
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

func GenerateIpv4Output(shellcode []byte) []string {
	if len(shellcode)%4 != 0 {
		return nil
	}
	var Output []string
	//fmt.Println("var Ipv4Array = []string{")
	for i := 0; i < len(shellcode); i += 4 {
		ipv4 := GenerateIpv4(
			int(shellcode[i]), int(shellcode[i+1]), int(shellcode[i+2]), int(shellcode[i+3]),
		)
		if i+4 < len(shellcode) {
			//fmt.Printf("\"%s\", ", ipv4)
		} else {
			//fmt.Printf("\"%s\"", ipv4)
		}
		if (i/4)%8 == 7 {
			//fmt.Println()
		}
		Output = append(Output, ipv4)
	}
	return Output
}
