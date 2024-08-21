package encryption

import (
	"fmt"
	"math/rand"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	AESKEYSIZE            = 32
	AESIVSIZE             = 16
	BCRYPT_AES_ALGORITHM  = windows.BCRYPT_AES_ALGORITHM
	BCRYPT_BLOCK_PADDING  = windows.BCRYPT_BLOCK_PADDING
	BCRYPT_CHAIN_MODE_CBC = windows.BCRYPT_CHAIN_MODE_CBC
	BCRYPT_OBJECT_LENGTH  = windows.BCRYPT_OBJECT_LENGTH
	BCRYPT_BLOCK_LENGTH   = windows.BCRYPT_BLOCK_LENGTH
)

type USTRING struct {
	Length        uint32
	MaximumLength uint32
	Buffer        *byte
}

type AES struct {
	PlainText  []byte
	PlainSize  uint32
	CipherText []byte
	CipherSize uint32
	Key        []byte
	Iv         []byte
}

type fnSystemFunction032 func(*USTRING, *USTRING) syscall.Errno

func GenerateRandomBytes(pByte []byte) {
	rand.Seed(time.Now().UnixNano())
	for i := range pByte {
		pByte[i] = byte(rand.Intn(256))
	}
}

func PrintHexData(Name string, Data []byte) {
	fmt.Printf("unsigned char %s[] = {", Name)
	for i, b := range Data {
		if i%16 == 0 {
			fmt.Printf("\n\t")
		}
		if i < len(Data)-1 {
			fmt.Printf("0x%0.2X, ", b)
		} else {
			fmt.Printf("0x%0.2X ", b)
		}
	}
	fmt.Printf("};\n\n\n")
}

func Rc4EncryptionViSystemFunc032(pRc4Key, pPayloadData []byte) error {
	Key := USTRING{
		Buffer:        &pRc4Key[0],
		Length:        uint32(len(pRc4Key)),
		MaximumLength: uint32(len(pRc4Key)),
	}
	Img := USTRING{
		Buffer:        &pPayloadData[0],
		Length:        uint32(len(pPayloadData)),
		MaximumLength: uint32(len(pPayloadData)),
	}

	advapi32, err := syscall.LoadLibrary("Advapi32.dll")
	if err != nil {
		return fmt.Errorf("failed to load Advapi32: %w", err)
	}
	defer syscall.FreeLibrary(advapi32)

	systemFunction032 := syscall.NewProc("SystemFunction032")
	if systemFunction032.Find() == syscall.Errno(0) {
		return fmt.Errorf("failed to find SystemFunction032")
	}
	systemFunction032Func := systemFunction032.Addr()
	var systemFunction032Fn fnSystemFunction032 = syscall.NewCallback(systemFunction032Func)

	status := systemFunction032Fn(&Img, &Key)
	if status != 0 {
		return fmt.Errorf("SystemFunction032 failed with error: 0x%0.8X", status)
	}
	return nil
}

func InstallAesEncryption(pAes *AES) error {
	var hAlgorithm, hKeyHandle windows.BCRYPT_ALG_HANDLE
	var cbResult, dwBlockSize, cbKeyObject uint32
	var pbKeyObject, pbCipherText []byte
	var status syscall.Errno

	status = windows.BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, nil, 0)
	if status != 0 {
		return fmt.Errorf("BCryptOpenAlgorithmProvider failed with error: 0x%0.8X", status)
	}
	defer windows.BCryptCloseAlgorithmProvider(hAlgorithm, 0)

	status = windows.BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (*byte)(unsafe.Pointer(&cbKeyObject)), unsafe.Sizeof(cbKeyObject), &cbResult, 0)
	if status != 0 {
		return fmt.Errorf("BCryptGetProperty[1] failed with error: 0x%0.8X", status)
	}

	status = windows.BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (*byte)(unsafe.Pointer(&dwBlockSize)), unsafe.Sizeof(dwBlockSize), &cbResult, 0)
	if status != 0 {
		return fmt.Errorf("BCryptGetProperty[2] failed with error: 0x%0.8X", status)
	}

	if dwBlockSize != 16 {
		return fmt.Errorf("block size is not 16")
	}

	pbKeyObject = make([]byte, cbKeyObject)

	status = windows.BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (*byte)(unsafe.Pointer(&BCRYPT_CHAIN_MODE_CBC)), unsafe.Sizeof(BCRYPT_CHAIN_MODE_CBC), 0)
	if status != 0 {
		return fmt.Errorf("BCryptSetProperty failed with error: 0x%0.8X", status)
	}

	status = windows.BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, &pbKeyObject[0], cbKeyObject, &pAes.Key[0], uint32(len(pAes.Key)), 0)
	if status != 0 {
		return fmt.Errorf("BCryptGenerateSymmetricKey failed with error: 0x%0.8X", status)
	}
	defer windows.BCryptDestroyKey(hKeyHandle)

	status = windows.BCryptEncrypt(hKeyHandle, &pAes.PlainText[0], uint32(len(pAes.PlainText)), nil, &pAes.Iv[0], uint32(len(pAes.Iv)), nil, 0, &cbCipherText, BCRYPT_BLOCK_PADDING)
	if status != 0 {
		return fmt.Errorf("BCryptEncrypt[1] failed with error: 0x%0.8X", status)
	}

	pbCipherText = make([]byte, cbCipherText)

	status = windows.BCryptEncrypt(hKeyHandle, &pAes.PlainText[0], uint32(len(pAes.PlainText)), nil, &pAes.Iv[0], uint32(len(pAes.Iv)), &pbCipherText[0], cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING)
	if status != 0 {
		return fmt.Errorf("BCryptEncrypt[2] failed with error: 0x%0.8X", status)
	}

	pAes.CipherText = pbCipherText
	pAes.CipherSize = cbCipherText

	return nil
}

func SimpleEncryption(pPlainTextData []byte, pKey, pIv []byte) ([]byte, error) {
	if len(pPlainTextData) == 0 || len(pKey) == 0 || len(pIv) == 0 {
		return nil, fmt.Errorf("invalid input data")
	}
	Aes := AES{
		Key:       pKey,
		Iv:        pIv,
		PlainText: pPlainTextData,
		PlainSize: uint32(len(pPlainTextData)),
	}

	err := InstallAesEncryption(&Aes)
	if err != nil {
		return nil, fmt.Errorf("failed to install AES encryption: %w", err)
	}
	return Aes.CipherText, nil
}

/*
func main() {
	// Example usage
	key := make([]byte, AESKEYSIZE)
	iv := make([]byte, AESIVSIZE)
	GenerateRandomBytes(key)
	GenerateRandomBytes(iv)

	plaintext := []byte("Hello, World!")
	ciphertext, err := SimpleEncryption(plaintext, key, iv)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Ciphertext:", ciphertext)

	PrintHexData("plaintext", plaintext)
	PrintHexData("key", key)
	PrintHexData("iv", iv)
	PrintHexData("ciphertext", ciphertext)
}
*/
