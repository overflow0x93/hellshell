package io

import (
	"fmt"
	"io/ioutil"
	"os"
)

// ReportError prints an error message and returns false.
func ReportError(apiName string) bool {
	fmt.Printf("[!] \"%s\" [ FAILED ] \t%d \n", apiName, os.GetLastError())
	return false
}

// ReadPayloadFile reads a file from disk and returns the data and size.
func ReadPayloadFile(filePath string, payloadSize *int, payloadData **[]byte) bool {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return ReportError("ReadFile")
	}

	*payloadData = &data
	*payloadSize = len(data)

	if *payloadData == nil || *payloadSize == 0 {
		return false
	}

	return true
}

// WritePayloadFile writes data to a file.
func WritePayloadFile(filePath string, payloadSize int, payloadData []byte) bool {
	err := ioutil.WriteFile(filePath, payloadData, 0644)
	if err != nil {
		return ReportError("WriteFile")
	}

	return true
}
